package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.adorsys.ssi.sdjwt.vp.KeyBindingJWT;
import com.adorsys.ssi.sdjwt.vp.KeyBindingJwtVerificationOpts;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runs SD-JWT verification in isolation with only essential properties.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVerificationContext {
    private String sdJwtVpString;

    private final IssuerSignedJWT issuerSignedJwt;
    private final Map<String, String> disclosures;
    private KeyBindingJWT keyBindingJwt;

    public SdJwtVerificationContext(
            String sdJwtVpString,
            IssuerSignedJWT issuerSignedJwt,
            Map<String, String> disclosures,
            KeyBindingJWT keyBindingJwt) {
        this(issuerSignedJwt, disclosures);
        this.keyBindingJwt = keyBindingJwt;
        this.sdJwtVpString = sdJwtVpString;
    }

    public SdJwtVerificationContext(IssuerSignedJWT issuerSignedJwt, Map<String, String> disclosures) {
        this.issuerSignedJwt = issuerSignedJwt;
        this.disclosures = disclosures;
    }

    public SdJwtVerificationContext(IssuerSignedJWT issuerSignedJwt, List<String> disclosureStrings) {
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
     * @param issuerSignedJwtVerificationOpts Options to parametize the Issuer-Signed JWT verification. A verifier
     *                                        must be specified for validating the Issuer-signed JWT. The caller
     *                                        is responsible for establishing trust in that associated public keys
     *                                        belong to the intended issuer.
     * @throws SdJwtVerificationException if verification failed
     */
    public void verifyIssuance(
            IssuerSignedJwtVerificationOpts issuerSignedJwtVerificationOpts
    ) throws SdJwtVerificationException {
        // Validate the Issuer-signed JWT.
        validateIssuerSignedJwt(issuerSignedJwtVerificationOpts.getVerifier());

        // Validate disclosures.
        var disclosedPayload = validateDisclosuresDigests();

        // Validate time claims.
        // Issuers will typically include claims controlling the validity of the SD-JWT in plaintext in the
        // SD-JWT payload, but there is no guarantee they would do so. Therefore, Verifiers cannot reliably
        // depend on that and need to operate as though security-critical claims might be selectively disclosable.
        validateIssuerSignedJwtTimeClaims(disclosedPayload, issuerSignedJwtVerificationOpts);
    }

    /**
     * Verifies SD-JWT presentation.
     *
     * <p>
     * Upon receiving a Presentation, in addition to the checks in {@link #verifyIssuance}, Verifiers need
     * to ensure that if Key Binding is required, the Key Binding JWT is signed by the Holder and valid.
     * </p>
     *
     * @param issuerSignedJwtVerificationOpts Options to parametize the Issuer-Signed JWT verification. A verifier
     *                                        must be specified for validating the Issuer-signed JWT. The caller
     *                                        is responsible for establishing trust in that associated public keys
     *                                        belong to the intended issuer.
     * @param keyBindingJwtVerificationOpts   Options to parametize the Key Binding JWT verification.
     *                                        Must, among others, specify the Verify's policy whether
     *                                        to check Key Binding.
     * @throws SdJwtVerificationException if verification failed
     */
    public void verifyPresentation(
            IssuerSignedJwtVerificationOpts issuerSignedJwtVerificationOpts,
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts
    ) throws SdJwtVerificationException {
        // If Key Binding is required and a Key Binding JWT is not provided,
        // the Verifier MUST reject the Presentation.
        if (keyBindingJwtVerificationOpts.isKeyBindingRequired() && keyBindingJwt == null) {
            throw new SdJwtVerificationException("Missing Key Binding JWT");
        }

        // Upon receiving a Presentation, in addition to the checks in {@link #verifyIssuance}...
        verifyIssuance(issuerSignedJwtVerificationOpts);

        // Validate Key Binding JWT if required
        if (keyBindingJwtVerificationOpts.isKeyBindingRequired()) {
            validateKeyBindingJwt(keyBindingJwtVerificationOpts);
        }
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
     * Validate Key Binding JWT
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateKeyBindingJwt(
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts
    ) throws SdJwtVerificationException {
        // Check that the typ of the Key Binding JWT is kb+jwt
        validateKeyBindingJwtTyp();

        // Determine the public key for the Holder from the SD-JWT
        var cnf = issuerSignedJwt.getCnfClaim().orElseThrow(
                () -> new SdJwtVerificationException("No cnf claim in Issuer-signed JWT for key binding")
        );

        // Ensure that a signing algorithm was used that was deemed secure for the application.
        // The none algorithm MUST NOT be accepted.
        var holderVerifier = buildHolderVerifier(cnf);

        // Validate the signature over the Key Binding JWT
        try {
            keyBindingJwt.verifySignature(holderVerifier);
        } catch (JOSEException e) {
            throw new SdJwtVerificationException("Key binding JWT invalid", e);
        }

        // Check that the creation time of the Key Binding JWT is within an acceptable window.
        validateKeyBindingJwtTimeClaims(keyBindingJwtVerificationOpts);

        // Determine that the Key Binding JWT is bound to the current transaction and was created
        // for this Verifier (replay protection) by validating nonce and aud claims.
        preventKeyBindingJwtReplay(keyBindingJwtVerificationOpts);

        // The same hash algorithm as for the Disclosures MUST be used (defined by the _sd_alg element
        // in the Issuer-signed JWT or the default value, as defined in Section 5.1.1).
        validateKeyBindingJwtSdHashIntegrity();

        // Check that the Key Binding JWT is a valid JWT in all other respects
        // -> Covered in part by `keyBindingJwt` being an instance of SdJws?
        // -> Time claims are checked above
    }

    /**
     * Validate Key Binding JWT's typ header attribute
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateKeyBindingJwtTyp() throws SdJwtVerificationException {
        var typ = keyBindingJwt.getHeader().get("typ");
        if (typ == null || !typ.isTextual() || !typ.asText().equals(KeyBindingJWT.TYP)) {
            throw new SdJwtVerificationException("Key Binding JWT is not of declared typ " + KeyBindingJWT.TYP);
        }
    }

    /**
     * Build holder verifier from JWK node.
     *
     * @throws SdJwtVerificationException if unable
     */
    private JWSVerifier buildHolderVerifier(JsonNode cnf) throws SdJwtVerificationException {
        Objects.requireNonNull(cnf);

        // Read JWK
        var cnfJwk = cnf.get("jwk");
        if (cnfJwk == null) {
            throw new UnsupportedOperationException("Only cnf/jwk claim supported");
        }

        // Parse JWK
        JWK jwk;
        try {
            jwk = JWK.parse(cnfJwk.toString());
        } catch (ParseException e) {
            throw new SdJwtVerificationException("Malformed cnf/jwk claim");
        }

        // Build verifier
        JWSVerifier verifier;
        try {
            if (KeyType.RSA.equals(jwk.getKeyType())) {
                verifier = new RSASSAVerifier(jwk.toRSAKey());
            } else if (KeyType.EC.equals(jwk.getKeyType())) {
                verifier = new ECDSAVerifier(jwk.toECKey());
            } else if (KeyType.OKP.equals(jwk.getKeyType())) {
                verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
            } else {
                throw new SdJwtVerificationException("cnf/jwk alg is unsupported or deemed not secure");
            }
        } catch (JOSEException e) {
            throw new SdJwtVerificationException("cnf/jwk is invalid");
        }

        return verifier;
    }

    /**
     * Validate Issuer-Signed JWT time claims.
     *
     * <p>
     * Check that the SD-JWT is valid using claims such as nbf, iat, and exp in the processed payload.
     * If a required validity-controlling claim is missing, the SD-JWT MUST be rejected.
     * </p>
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateIssuerSignedJwtTimeClaims(
            JsonNode payload,
            IssuerSignedJwtVerificationOpts issuerSignedJwtVerificationOpts
    ) throws SdJwtVerificationException {
        long now = Instant.now().getEpochSecond();

        try {
            if (issuerSignedJwtVerificationOpts.mustValidateIssuedAtClaim()
                    && now < SdJwtUtils.readTimeClaim(payload, "iat")) {
                throw new SdJwtVerificationException("JWT issued in the future");
            }
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Issuer-Signed JWT: Invalid `iat` claim", e);
        }

        try {
            if (issuerSignedJwtVerificationOpts.mustValidateExpirationClaim()
                    && now >= SdJwtUtils.readTimeClaim(payload, "exp")) {
                throw new SdJwtVerificationException("JWT has expired");
            }
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Issuer-Signed JWT: Invalid `exp` claim", e);
        }

        try {
            if (issuerSignedJwtVerificationOpts.mustValidateNotBeforeClaim()
                    && now < SdJwtUtils.readTimeClaim(payload, "nbf")) {
                throw new SdJwtVerificationException("JWT is not yet valid");
            }
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Issuer-Signed JWT: Invalid `nbf` claim", e);
        }
    }

    /**
     * Validate key binding JWT time claims.
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateKeyBindingJwtTimeClaims(
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts
    ) throws SdJwtVerificationException {
        // Check that the creation time of the Key Binding JWT, as determined by the iat claim,
        // is within an acceptable window

        try {
            keyBindingJwt.verifyIssuedAtClaim();
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Key binding JWT: Invalid `iat` claim", e);
        }

        long keyBindingJwtIat = SdJwtUtils.readTimeClaim(keyBindingJwt.getPayload(), "iat");
        Long issuerSignedJwtIat = null;

        try {
            issuerSignedJwtIat = SdJwtUtils.readTimeClaim(issuerSignedJwt.getPayload(), "iat");
        } catch (SdJwtVerificationException ignored) {
        }

        if (issuerSignedJwtIat != null && keyBindingJwtIat < issuerSignedJwtIat) {
            throw new SdJwtVerificationException("Key binding JWT was issued before Issuer-signed JWT");
        }

        // Check other time claims

        try {
            if (keyBindingJwtVerificationOpts.mustValidateExpirationClaim()) {
                keyBindingJwt.verifyExpClaim();
            }
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Key binding JWT: Invalid `exp` claim", e);
        }

        try {
            if (keyBindingJwtVerificationOpts.mustValidateNotBeforeClaim()) {
                keyBindingJwt.verifyNotBeforeClaim();
            }
        } catch (SdJwtVerificationException e) {
            throw new SdJwtVerificationException("Key binding JWT: Invalid `nbf` claim", e);
        }
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
            throw new SdJwtVerificationException("A field disclosure must contain exactly three elements");
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
            throw new SdJwtVerificationException("An array element disclosure must contain exactly two elements");
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

    /**
     * Run checks for replay protection.
     *
     * <p>
     * Determine that the Key Binding JWT is bound to the current transaction and was created for this
     * Verifier (replay protection) by validating nonce and aud claims.
     * </p>
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void preventKeyBindingJwtReplay(
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts
    ) throws SdJwtVerificationException {
        JsonNode nonce = keyBindingJwt.getPayload().get("nonce");
        if (nonce == null || !nonce.isTextual()
                || !nonce.asText().equals(keyBindingJwtVerificationOpts.getNonce())) {
            throw new SdJwtVerificationException("Key binding JWT: Unexpected `nonce` value");
        }

        JsonNode aud = keyBindingJwt.getPayload().get("aud");
        if (aud == null || !aud.isTextual()
                || !aud.asText().equals(keyBindingJwtVerificationOpts.getAud())) {
            throw new SdJwtVerificationException("Key binding JWT: Unexpected `aud` value");
        }
    }

    /**
     * Validate integrity of Key Binding JWT's sd_hash.
     *
     * <p>
     * Calculate the digest over the Issuer-signed JWT and Disclosures and verify that it matches
     * the value of the sd_hash claim in the Key Binding JWT.
     * </p>
     *
     * @throws SdJwtVerificationException if verification failed
     */
    private void validateKeyBindingJwtSdHashIntegrity() throws SdJwtVerificationException {
        Objects.requireNonNull(sdJwtVpString);

        JsonNode sdHash = keyBindingJwt.getPayload().get("sd_hash");
        if (sdHash == null || !sdHash.isTextual()) {
            throw new SdJwtVerificationException("Key binding JWT: Claim `sd_hash` missing or not a string");
        }

        int lastDelimiterIndex = sdJwtVpString.lastIndexOf(SdJwt.DELIMITER);
        String toHash = sdJwtVpString.substring(0, lastDelimiterIndex + 1);

        String digest = SdJwtUtils.hashAndBase64EncodeNoPad(
                toHash.getBytes(), issuerSignedJwt.getSdHashAlg());

        if (!digest.equals(sdHash.asText())) {
            throw new SdJwtVerificationException("Key binding JWT: Invalid `sd_hash` digest");
        }
    }
}
