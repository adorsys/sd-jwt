package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Runs SD-JWT verification in isolation with only essential properties.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
class SdJwtVerificationContext {

    private final IssuerSignedJWT issuerSignedJwt;
    private final Map<String, String> disclosures;

    SdJwtVerificationContext(IssuerSignedJWT issuerSignedJwt, Map<String, String> disclosures) {
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = disclosures;
    }

    SdJwtVerificationContext(IssuerSignedJWT issuerSignedJwt, List<String> disclosureStrings) {
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = computeDigestDisclosureMap(disclosureStrings);
    }

    private Map<String, String> computeDigestDisclosureMap(List<String> disclosureStrings) {
        return disclosureStrings.stream()
                .map(disclosureString -> {
                    var digest = SdJwtUtils.hashAndBase64EncodeNoPad(
                            disclosureString.getBytes(), issuerSignedJwt.getSdHashAlg());
                    return Map.entry(digest, disclosureString);
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
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
    void verifyIssuance(SdJwtVerificationOptions verificationOptions) throws SdJwtVerificationException {
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
            throw new SdJwtVerificationException("JWT issued in the future");
        }

        if (verificationOptions.mustValidateExpirationClaim()
                && now >= readTimeClaim(payload, "exp")) {
            throw new SdJwtVerificationException("JWT has expired");
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
        // Validate SdJwt digests by attempting full recursive disclosing.
        Set<String> visitedDigests = new HashSet<>();
        Set<String> visitedDisclosureStrings = new HashSet<>();
        var disclosedPayload = validateViaRecursiveDisclosing(
                issuerSignedJwt.getPayload(), visitedDigests, visitedDisclosureStrings);

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
            Set<String> visitedDigests,
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
                    markDigestAsVisited(digest, visitedDigests);
                    var disclosure = disclosures.get(digest);

                    if (disclosure != null) {
                        // Mark disclosure as visited
                        visitedDisclosureStrings.add(disclosure);

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
                        markDigestAsVisited(digest, visitedDigests);
                        var disclosure = disclosures.get(digest);

                        if (disclosure != null) {
                            // Mark disclosure as visited
                            visitedDisclosureStrings.add(disclosure);

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
            validateViaRecursiveDisclosing(childNode, visitedDigests, visitedDisclosureStrings);
        }

        return currentNode;
    }

    /**
     * Mark digest as visited.
     *
     * <p>
     * If any digest value is encountered more than once in the Issuer-signed JWT payload
     * (directly or recursively via other Disclosures), the SD-JWT MUST be rejected.
     * </p>
     *
     * @throws SdJwtVerificationException if not first visit
     */
    private void markDigestAsVisited(String digest, Set<String> visitedDigests)
            throws SdJwtVerificationException {
        if (!visitedDigests.add(digest)) {
            // If add returns false, then it is a duplicate
            throw new SdJwtVerificationException("A digest was encounted more than once: " + digest);
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
}
