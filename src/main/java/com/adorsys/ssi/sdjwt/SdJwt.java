
package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.adorsys.ssi.sdjwt.vp.KeyBindingJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Main entry class for selective disclosure jwt (SD-JWT).
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class SdJwt {
    public static final String DELIMITER = "~";

    private final IssuerSignedJWT issuerSignedJWT;
    private final List<SdJwtClaim> claims;
    private final List<String> disclosures = new ArrayList<>();
    private Optional<String> sdJwtString = Optional.empty();

    private SdJwt(DisclosureSpec disclosureSpec, JsonNode claimSet, List<SdJwt> nesteSdJwts,
                  Optional<KeyBindingJWT> keyBindingJWT,
                  JWSSigner signer,
                  String keyId,
                  String hashAlgorithm,
                  String jwsType) {
        claims = new ArrayList<>();
        claimSet.fields()
                .forEachRemaining(entry -> claims.add(createClaim(entry.getKey(), entry.getValue(), disclosureSpec)));

        this.issuerSignedJWT = IssuerSignedJWT.builder()
                .withClaims(claims)
                .withDecoyClaims(createdDecoyClaims(disclosureSpec))
                .withNestedDisclosures(!nesteSdJwts.isEmpty())
                .withSigner(signer)
                .withKeyId(keyId)
                .withHashAlg(hashAlgorithm)
                .withJwsType(jwsType)
                .build();

        nesteSdJwts.forEach(nestedJwt -> this.disclosures.addAll(nestedJwt.getDisclosures()));
        this.disclosures.addAll(getDisclosureStrings(claims));
    }

    private List<DecoyClaim> createdDecoyClaims(DisclosureSpec disclosureSpec) {
        return disclosureSpec.getDecoyClaims().stream()
                .map(disclosureData -> DecoyClaim.builder().withSalt(disclosureData.getSalt()).build())
                .collect(Collectors.toList());
    }

    /**
     * Prepare to a nested payload to this SD-JWT.
     * <p>
     * dropping the algo claim.
     */
    public JsonNode asNestedPayload() {
        JsonNode nestedPayload = issuerSignedJWT.getPayload();
        ((ObjectNode) nestedPayload).remove(IssuerSignedJWT.CLAIM_NAME_SD_HASH_ALGORITHM);
        return nestedPayload;
    }

    public String toSdJwtString() {
        List<String> parts = new ArrayList<>();

        parts.add(issuerSignedJWT.toJws());
        parts.addAll(disclosures);
        parts.add("");

        return String.join(DELIMITER, parts);
    }

    private static List<String> getDisclosureStrings(List<SdJwtClaim> claims) {
        List<String> disclosureStrings = new ArrayList<>();
        claims.stream()
                .map(SdJwtClaim::getDisclosureStrings)
                .forEach(disclosureStrings::addAll);
        return Collections.unmodifiableList(disclosureStrings);
    }

    @Override
    public String toString() {
        return sdJwtString.orElseGet(() -> {
            String sdString = toSdJwtString();
            sdJwtString = Optional.of(sdString);
            return sdString;
        });
    }

    private SdJwtClaim createClaim(String claimName, JsonNode claimValue, DisclosureSpec disclosureSpec) {
        DisclosureSpec.DisclosureData disclosureData = disclosureSpec.getUndisclosedClaim(SdJwtClaimName.of(claimName));

        if (disclosureData != null) {
            return createUndisclosedClaim(claimName, claimValue, disclosureData.getSalt());
        } else {
            return createArrayOrVisibleClaim(claimName, claimValue, disclosureSpec);
        }
    }

    private SdJwtClaim createUndisclosedClaim(String claimName, JsonNode claimValue, SdJwtSalt salt) {
        return UndisclosedClaim.builder()
                .withClaimName(claimName)
                .withClaimValue(claimValue)
                .withSalt(salt)
                .build();
    }

    private SdJwtClaim createArrayOrVisibleClaim(String claimName, JsonNode claimValue, DisclosureSpec disclosureSpec) {
        SdJwtClaimName sdJwtClaimName = SdJwtClaimName.of(claimName);
        Map<Integer, DisclosureSpec.DisclosureData> undisclosedArrayElts = disclosureSpec
                .getUndisclosedArrayElts(sdJwtClaimName);
        Map<Integer, DisclosureSpec.DisclosureData> decoyArrayElts = disclosureSpec.getDecoyArrayElts(sdJwtClaimName);

        if (undisclosedArrayElts != null || decoyArrayElts != null) {
            return createArrayDisclosure(claimName, claimValue, undisclosedArrayElts, decoyArrayElts);
        } else {
            return VisibleSdJwtClaim.builder()
                    .withClaimName(claimName)
                    .withClaimValue(claimValue)
                    .build();
        }
    }

    private SdJwtClaim createArrayDisclosure(String claimName, JsonNode claimValue,
                                             Map<Integer, DisclosureSpec.DisclosureData> undisclosedArrayElts,
                                             Map<Integer, DisclosureSpec.DisclosureData> decoyArrayElts) {
        ArrayNode arrayNode = validateArrayNode(claimName, claimValue);
        ArrayDisclosure.Builder arrayDisclosureBuilder = ArrayDisclosure.builder().withClaimName(claimName);

        if (undisclosedArrayElts != null) {
            IntStream.range(0, arrayNode.size())
                    .forEach(i -> processArrayElement(arrayDisclosureBuilder, arrayNode.get(i),
                            undisclosedArrayElts.get(i)));
        }

        if (decoyArrayElts != null) {
            decoyArrayElts.forEach((key, value) -> arrayDisclosureBuilder.withDecoyElt(key, value.getSalt()));
        }

        return arrayDisclosureBuilder.build();
    }

    private ArrayNode validateArrayNode(String claimName, JsonNode claimValue) {
        return Optional.of(claimValue)
                .filter(v -> v.getNodeType() == JsonNodeType.ARRAY)
                .map(v -> (ArrayNode) v)
                .orElseThrow(
                        () -> new IllegalArgumentException("Expected array for claim with name: " + claimName));
    }

    private void processArrayElement(ArrayDisclosure.Builder builder, JsonNode elementValue,
                                     DisclosureSpec.DisclosureData disclosureData) {
        if (disclosureData != null) {
            builder.withUndisclosedElement(disclosureData.getSalt(), elementValue);
        } else {
            builder.withVisibleElement(elementValue);
        }
    }

    public IssuerSignedJWT getIssuerSignedJWT() {
        return issuerSignedJWT;
    }

    public List<String> getDisclosures() {
        return disclosures;
    }

    /**
     * Verifies SD-JWT as to whether the Issuer-signed JWT's signature and disclosures are valid.
     *
     * <p>Upon receiving an SD-JWT, a Holder or a Verifier needs to ensure that:</p>
     * - the Issuer-signed JWT is valid, i.e., it is signed by the Issuer and the signature is valid, and
     * - all Disclosures are valid and correspond to a respective digest value in the Issuer-signed JWT
     * (directly in the payload or recursively included in the contents of other Disclosures).
     *
     * @param verificationOptions Options to parametize the verification. A verifier must be specified
     *                            for validating the Issuer-signed JWT. The caller is responsible for
     *                            establishing trust in that associated public keys belong to the
     *                            intended issuer.
     * @throws SdJwtVerificationException if verification failed
     */
    public void verify(SdJwtVerificationOptions verificationOptions) throws SdJwtVerificationException {
        // Validate the Issuer-signed JWT.
        validateIssuerSignedJwt(verificationOptions.getVerifier());

        // Validate disclosures.
        var disclosedPayload = validateDisclosuresDigests();

        // Validate time claims.
        // Issuers will typically include claims controlling the validity of the SD-JWT in plaintext in the
        // SD-JWT payload, but there is no guarantee they would do so. Therefore, Verifiers cannot reliably
        // depend on that and need to operate as though security-critical claims might be selectively disclosable.
        validateTimeClaims(disclosedPayload, verificationOptions);
    }

    /**
     * Validate Issuer-signed JWT
     *
     * <p>
     * Upon receiving an SD-JWT, a Holder or a Verifier needs to ensure that:
     * - the Issuer-signed JWT is valid, i.e., it is signed by the Issuer and the signature is valid
     * </p>
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateIssuerSignedJwt(JWSVerifier verifier) throws SdJwtVerificationException {
        var issuerSignedJwt = getIssuerSignedJWT();

        // Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure
        issuerSignedJwt.verifySdHashAlgorithm();

        // Validate the signature over the Issuer-signed JWT
        try {
            issuerSignedJwt.verifySignature(verifier);
        } catch (JOSEException e) {
            throw new SdJwtVerificationException("Invalid Issuer-Signed JWT", e);
        }
    }

    /**
     * Validate time claims.
     *
     * <p>
     * Check that the SD-JWT is valid using claims such as nbf, iat, and exp in the processed payload.
     * If a required validity-controlling claim is missing, the SD-JWT MUST be rejected.
     * </p>
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateTimeClaims(JsonNode payload, SdJwtVerificationOptions verificationOptions)
            throws SdJwtVerificationException {
        long now = Instant.now().getEpochSecond();

        if (verificationOptions.mustValidateIssuedAtClaim()
                && now < readTimeClaim(payload, "iat")) {
            throw new SdJwtVerificationException("JWT is issued in the future");
        }

        if (verificationOptions.mustValidateExpirationClaim()
                && now >= readTimeClaim(payload, "exp")) {
            throw new SdJwtVerificationException("JWT is expired");
        }

        if (verificationOptions.mustValidateNotBeforeClaim()
                && now < readTimeClaim(payload, "nbf")) {
            throw new SdJwtVerificationException("JWT is not yet valid");
        }
    }

    private long readTimeClaim(JsonNode payload, String claimName) throws SdJwtVerificationException {
        JsonNode claim = payload.get(claimName);
        if (claim == null || !claim.isNumber()) {
            throw new SdJwtVerificationException("Missing or invalid '" + claimName + "' claim");
        }

        return claim.asLong();
    }

    /**
     * Validate disclosures' digests
     *
     * <p>
     * Upon receiving an SD-JWT, a Holder or a Verifier needs to ensure that:
     * - all Disclosures are valid and correspond to a respective digest value in the Issuer-signed JWT
     * (directly in the payload or recursively included in the contents of other Disclosures)
     * </p>
     *
     * @return the fully disclosed SdJwt payload
     * @throws SdJwtVerificationException if verification failed
     */
    private JsonNode validateDisclosuresDigests() throws SdJwtVerificationException {
        var issuerSignedJwt = getIssuerSignedJWT();

        // Map disclosures (value) to their digests (key)
        var disclosureMap = computeIssuerSignedJwtDigestDisclosureMap();

        // Validate SdJwt digests by attempting full recursive disclosing.
        Set<String> visitedDisclosureStrings = new HashSet<>();
        var disclosedPayload = validateViaRecursiveDisclosing(
                issuerSignedJwt.getPayload(), disclosureMap, visitedDisclosureStrings);

        // Validate all disclosures where visited
        validateDisclosuresVisits(visitedDisclosureStrings);

        return disclosedPayload;
    }

    /**
     * Validate SdJwt digests by attempting full recursive disclosing.
     *
     * <p>
     * By recursively disclosing all disclosable fields in the SdJwt payload, validation rules are
     * enforced regarding the conformance of linked disclosures. Additional rules should be enforced
     * after calling this method based on the visited data arguments.
     * </p>
     *
     * @return the fully disclosed SdJwt payload
     */
    private JsonNode validateViaRecursiveDisclosing(
            JsonNode currentNode,
            Map<String, String> disclosureMap,
            Set<String> visitedDisclosureStrings
    ) throws SdJwtVerificationException {
        if (!currentNode.isObject() && !currentNode.isArray()) {
            return currentNode;
        }

        // Find all objects having an _sd key that refers to an array of strings.
        if (currentNode.isObject()) {
            var currentObjectNode = ((ObjectNode) currentNode);

            var sdArray = currentObjectNode.get(IssuerSignedJWT.CLAIM_NAME_SELECTIVE_DISCLOSURE);
            if (sdArray != null && sdArray.isArray()) {
                for (var el : sdArray) {
                    if (!el.isTextual()) {
                        throw new SdJwtVerificationException(
                                "Unexpected non-string element inside _sd array: " + el
                        );
                    }

                    // Compare the value with the digests calculated previously and find the matching Disclosure.
                    // If no such Disclosure can be found, the digest MUST be ignored.

                    var digest = el.asText();
                    var disclosure = disclosureMap.get(digest);

                    if (disclosure != null) {
                        // Mark disclosure as visited
                        markDisclosureAsVisited(disclosure, visitedDisclosureStrings);

                        // Validate disclosure format
                        var claim = validateSdArrayDigestDisclosureFormat(disclosure);

                        // Insert, at the level of the _sd key, a new claim using the claim name
                        // and claim value from the Disclosure
                        currentObjectNode.set(
                                claim.getClaimNameAsString(),
                                claim.getVisibleClaimValue(null)
                        );
                    }
                }
            }

            // Remove all _sd keys and their contents from the Issuer-signed JWT payload.
            // If this results in an object with no properties, it should be represented as an empty object {}
            currentObjectNode.remove(IssuerSignedJWT.CLAIM_NAME_SELECTIVE_DISCLOSURE);

            // Remove the claim _sd_alg from the SD-JWT payload.
            currentObjectNode.remove(IssuerSignedJWT.CLAIM_NAME_SD_HASH_ALGORITHM);
        }

        // Find all array elements that are objects with one key, that key being ... and referring to a string
        if (currentNode.isArray()) {
            var currentArrayNode = ((ArrayNode) currentNode);
            var indexesToRemove = new ArrayList<Integer>();

            for (int i = 0; i < currentArrayNode.size(); ++i) {
                var itemNode = currentArrayNode.get(i);
                if (itemNode.isObject() && itemNode.size() == 1) {
                    // Check single "..." field
                    var field = itemNode.fields().next();
                    if (field.getKey().equals(UndisclosedArrayElement.SD_CLAIM_NAME)
                            && field.getValue().isTextual()) {
                        // Compare the value with the digests calculated previously and find the matching Disclosure.
                        // If no such Disclosure can be found, the digest MUST be ignored.

                        var digest = field.getValue().asText();
                        var disclosure = disclosureMap.get(digest);

                        if (disclosure != null) {
                            // Mark disclosure as visited
                            markDisclosureAsVisited(disclosure, visitedDisclosureStrings);

                            // Validate disclosure format
                            var claimValue = validateArrayElementDigestDisclosureFormat(disclosure);

                            // Replace the array element with the value from the Disclosure.
                            // Removal is done below.
                            currentArrayNode.set(i, claimValue);
                        } else {
                            // Remove all array elements for which the digest was not found in the previous step.
                            indexesToRemove.add(i);
                        }
                    }
                }
            }

            // Remove all array elements for which the digest was not found in the previous step.
            indexesToRemove.forEach(currentArrayNode::remove);
        }

        for (JsonNode childNode : currentNode) {
            validateViaRecursiveDisclosing(childNode, disclosureMap, visitedDisclosureStrings);
        }

        return currentNode;
    }

    /**
     * Mark disclosure as visited.
     *
     * <p>
     * If any digest value is encountered more than once in the Issuer-signed JWT payload
     * (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
     * </p>
     *
     * @throws SdJwtVerificationException if not first visit
     */
    private void markDisclosureAsVisited(String disclosure, Set<String> visitedDisclosureStrings)
            throws SdJwtVerificationException {
        if (!visitedDisclosureStrings.add(disclosure)) {
            // If add returns false, then it is a duplicate
            throw new SdJwtVerificationException("A digest was encounted more than once: " + disclosure);
        }
    }

    /**
     * Validate disclosure assuming digest was found in an object's _sd key.
     *
     * <p>
     * If the contents of the respective Disclosure is not a JSON-encoded array of three elements
     * (salt, claim name, claim value), the SD-JWT MUST be rejected.
     * </p>
     *
     * <p>
     * If the claim name is _sd or ..., the SD-JWT MUST be rejected.
     * </p>
     *
     * @return decoded disclosure as visible claim
     */
    private VisibleSdJwtClaim validateSdArrayDigestDisclosureFormat(String disclosure)
            throws SdJwtVerificationException {
        ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);

        // Check if the array has exactly three elements
        if (arrayNode.size() != 3) {
            throw new SdJwtVerificationException("Disclosure does not contain exactly three elements");
        }

        // If the claim name is _sd or ..., the SD-JWT MUST be rejected.

        var denylist = List.of(
                IssuerSignedJWT.CLAIM_NAME_SELECTIVE_DISCLOSURE,
                UndisclosedArrayElement.SD_CLAIM_NAME
        );

        String claimName = arrayNode.get(1).asText();
        if (denylist.contains(claimName)) {
            throw new SdJwtVerificationException("Disclosure claim name must not be '_sd' or '...'");
        }

        // Build claim
        return VisibleSdJwtClaim.builder()
                .withClaimName(arrayNode.get(1).asText())
                .withClaimValue(arrayNode.get(2))
                .build();
    }

    /**
     * Validate disclosure assuming digest was found as an undisclosed array element.
     *
     * <p>
     * If the contents of the respective Disclosure is not a JSON-encoded array of
     * two elements (salt, value), the SD-JWT MUST be rejected.
     * </p>
     *
     * @return decoded disclosure as visible claim (value only)
     */
    private JsonNode validateArrayElementDigestDisclosureFormat(String disclosure)
            throws SdJwtVerificationException {
        ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);

        // Check if the array has exactly two elements
        if (arrayNode.size() != 2) {
            throw new SdJwtVerificationException("Disclosure does not contain exactly two elements");
        }

        // Return value
        return arrayNode.get(1);
    }

    /**
     * Validate all disclosures where visited
     *
     * <p>
     * If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via
     * other Disclosures), the SD-JWT MUST be rejected.
     * </p>
     *
     * @throws SdJwtVerificationException if not the case
     */
    private void validateDisclosuresVisits(Set<String> visitedDisclosureStrings)
            throws SdJwtVerificationException {
        if (visitedDisclosureStrings.size() < disclosures.size()) {
            throw new SdJwtVerificationException("At least one disclosure is not protected by digest");
        }
    }

    private Map<String, String> computeIssuerSignedJwtDigestDisclosureMap() {
        return disclosures.stream()
                .map(disclosure -> {
                    var digest = SdJwtUtils.hashAndBase64EncodeNoPad(
                            disclosure.getBytes(), getIssuerSignedJWT().getSdHashAlg());
                    return Map.entry(digest, disclosure);
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    // builder for SdJwt
    public static class Builder {
        private DisclosureSpec disclosureSpec;
        private JsonNode claimSet;
        private Optional<KeyBindingJWT> keyBindingJWT = Optional.empty();
        private JWSSigner signer;
        private final List<SdJwt> nestedSdJwts = new ArrayList<>();
        private String hashAlgorithm;
        private String jwsType;
        private String keyId;

        public Builder withDisclosureSpec(DisclosureSpec disclosureSpec) {
            this.disclosureSpec = disclosureSpec;
            return this;
        }

        public Builder withClaimSet(JsonNode claimSet) {
            this.claimSet = claimSet;
            return this;
        }

        public Builder withKeyBindingJWT(KeyBindingJWT keyBindingJWT) {
            this.keyBindingJWT = Optional.of(keyBindingJWT);
            return this;
        }

        public Builder withSigner(JWSSigner signer) {
            this.signer = signer;
            return this;
        }

        public Builder withKeyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder withNestedSdJwt(SdJwt nestedSdJwt) {
            nestedSdJwts.add(nestedSdJwt);
            return this;
        }

        public Builder withHashAlgorithm(String hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
            return this;
        }

        public Builder withJwsType(String jwsType) {
            this.jwsType = jwsType;
            return this;
        }

        public SdJwt build() {
            return new SdJwt(disclosureSpec, claimSet, nestedSdJwts, keyBindingJWT, signer, keyId, hashAlgorithm, jwsType);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
