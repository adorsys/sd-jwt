
package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.vp.KeyBindingJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
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

        nesteSdJwts.stream().forEach(nestedJwt -> this.disclosures.addAll(nestedJwt.getDisclosures()));
        this.disclosures.addAll(getDisclosureStrings(claims));
    }

    private Optional<String> sdJwtString = Optional.empty();

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
            decoyArrayElts.entrySet().stream()
                    .forEach(e -> arrayDisclosureBuilder.withDecoyElt(e.getKey(), e.getValue().getSalt()));
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
     * @param verifier Context to validate the Issuer-signed JWT. The caller is responsible for
     *                 establishing trust in that associated public keys belong to the issuer.
     * @throws GeneralSecurityException if verification failed
     */
    public void verify(JWSVerifier verifier) throws GeneralSecurityException {
        // Validate the Issuer-signed JWT
        validateIssuerSignedJwt(verifier);

        // Validate disclosures
        validateDisclosuresDigests();
    }

    private void validateIssuerSignedJwt(JWSVerifier verifier) throws GeneralSecurityException {
        var issuerSignedJwt = getIssuerSignedJWT();

        // Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure
        issuerSignedJwt.verifySdHashAlgorithm();

        // Validate the signature over the Issuer-signed JWT
        try {
            issuerSignedJwt.verifySignature(verifier);
        } catch (JOSEException e) {
            throw new SignatureException("Invalid Issuer-Signed JWT", e);
        }
    }

    private void validateDisclosuresDigests() throws GeneralSecurityException {
        // Identify all embedded digests in the Issuer-signed JWT
        var digests = collectAllDigests(getIssuerSignedJWT().getPayload());
        System.out.println(digests);

        // Recalculate digests
//        var recalculatedDigests = disclosures.stream()
//                .map(String::getBytes)
//                .map(bytes -> SdJwtUtils.encodeNoPad(SdJwtUtils.hash(bytes, )))
    }

    // Recursively collect all digests.
    private List<String> collectAllDigests(JsonNode node) {
        var collected = new ArrayList<String>();

        if (!node.isObject() && !node.isArray()) {
            return collected;
        }

        if (node.isObject()) {
            // Collect "_sd" arrays
            var sdArray = node.get(IssuerSignedJWT.CLAIM_NAME_SELECTIVE_DISCLOSURE);
            if (sdArray != null && sdArray.isArray()) {
                sdArray.forEach(el -> collected.add(el.asText()));
            }

            // Collect "..." fields — It must be the only field of the current node
            var it = node.fields();
            var field = it.next();
            if (!it.hasNext() && field != null && field.getKey().equals("...")) {
                collected.add(field.getValue().asText());
            }
        }

        for (JsonNode child : node) {
            collected.addAll(collectAllDigests(child));
        }

        return collected;
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
