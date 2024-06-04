
package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Handle verifiable credentials (SD-JWT VC), enabling the parsing
 * of existing VCs as well as the creation and signing of new ones.
 * It integrates with JOSE's JWSSigner to facilitate
 * the generation of issuer signature.
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class IssuerSignedJWT extends SdJws {

    public IssuerSignedJWT(JsonNode payload, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        super(payload, signer, keyId, jwsAlgorithm, jwsType);
    }

    public IssuerSignedJWT(Base64URL payloadBase64URL, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        super(payloadBase64URL, signer, keyId, jwsAlgorithm, jwsType);
    }

    public static IssuerSignedJWT fromJws(String jwsString) {
        return new IssuerSignedJWT(jwsString);
    }

    private IssuerSignedJWT(String jwsString) {
        super(jwsString);
    }

    private IssuerSignedJWT(List<SdJwtClaim> claims, List<DecoyClaim> decoyClaims, String hashAlg,
                            boolean nestedDisclosures) {
        super(generatePayloadString(claims, decoyClaims, hashAlg, nestedDisclosures));
    }

    private IssuerSignedJWT(JsonNode payload, JWSObject jwsInput) {
        super(payload, jwsInput);
    }

    private IssuerSignedJWT(List<SdJwtClaim> claims, List<DecoyClaim> decoyClaims, String hashAlg,
                            boolean nestedDisclosures, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        super(generatePayloadString(claims, decoyClaims, hashAlg, nestedDisclosures), signer, keyId, jwsAlgorithm, jwsType);
    }

    /*
     * Generates the payload of the issuer signed jwt from the list
     * of claims.
     */
    private static JsonNode generatePayloadString(List<SdJwtClaim> claims, List<DecoyClaim> decoyClaims, String hashAlg,
                                                  boolean nestedDisclosures) {

        SdJwtUtils.requireNonEmpty(hashAlg, "hashAlg must not be null or empty");
        final List<SdJwtClaim> claimsInternal = claims == null ? Collections.emptyList()
                : Collections.unmodifiableList(claims);
        final List<DecoyClaim> decoyClaimsInternal = decoyClaims == null ? Collections.emptyList()
                : Collections.unmodifiableList(decoyClaims);
        try {
            // Check no dupplicate claim names
            claimsInternal.stream()
                    .filter(Objects::nonNull)
                    // is any duplicate, toMap will throw IllegalStateException
                    .collect(Collectors.toMap(SdJwtClaim::getClaimName, claim -> claim));
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("claims must not contain duplicate claim names", e);
        }

        ArrayNode sdArray = SdJwtUtils.mapper.createArrayNode();
        // first filter all UndisclosedClaim
        // then sort by salt
        // then push digest into the sdArray
        List<String> digests = claimsInternal.stream()
                .filter(claim -> claim instanceof UndisclosedClaim)
                .map(claim -> (UndisclosedClaim) claim)
                .collect(Collectors.toMap(UndisclosedClaim::getSalt, claim -> claim))
                .entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(Map.Entry::getValue)
                .filter(Objects::nonNull)
                .map(od -> od.getDisclosureDigest(hashAlg))
                .collect(Collectors.toList());

        // add decoy claims
        decoyClaimsInternal.stream().map(claim -> claim.getDisclosureDigest(hashAlg)).forEach(digests::add);

        digests.stream().sorted().forEach(sdArray::add);

        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();

        if (!sdArray.isEmpty()) {
            // drop _sd claim if empty
            payload.set(CLAIM_NAME_SELECTIVE_DISCLOSURE, sdArray);
        }
        if (!sdArray.isEmpty() || nestedDisclosures) {
            // add sd alg only if ay disclosure.
            payload.put(CLAIM_NAME_SD_HASH_ALGORITHM, hashAlg);
        }

        // then put all other claims in the paypload
        // Disclosure of array of elements is handled
        // by the corresponding claim object.
        claimsInternal.stream()
                .filter(Objects::nonNull)
                .filter(claim -> !(claim instanceof UndisclosedClaim))
                .forEach(nullableClaim -> {
                    SdJwtClaim claim = Objects.requireNonNull(nullableClaim);
                    payload.set(claim.getClaimNameAsString(), claim.getVisibleClaimValue(hashAlg));
                });

        return payload;
    }

    /**
     * Returns Cnf claim (establishing key binding)
     */
    public Optional<JsonNode> getCnfClaim() {
        var cnf = getPayload().get("cnf");
        return Optional.ofNullable(cnf);
    }

    /**
     * Returns declared hash algorithm from SD hash claim.
     */
    public String getSdHashAlg() {
        var hashAlgNode = getPayload().get(CLAIM_NAME_SD_HASH_ALGORITHM);
        return hashAlgNode == null ? "sha-256" : hashAlgNode.asText();
    }

    /**
     * Verifies that the SD hash algorithm is understood and deemed secure.
     *
     * @throws SdJwtVerificationException if not
     */
    public void verifySdHashAlgorithm() throws SdJwtVerificationException {
        // Known secure algorithms
        final Set<String> secureAlgorithms = Set.of(
                "sha-256", "sha-384", "sha-512",
                "sha3-256", "sha3-384", "sha3-512"
        );

        // Read SD hash claim
        String hashAlg = getSdHashAlg();

        // Safeguard algorithm
        if (!secureAlgorithms.contains(hashAlg)) {
            throw new SdJwtVerificationException("Unexpected or insecure hash algorithm: " + hashAlg);
        }
    }

    // SD-JWT Claims
    public static final String CLAIM_NAME_SELECTIVE_DISCLOSURE = "_sd";
    public static final String CLAIM_NAME_SD_HASH_ALGORITHM = "_sd_alg";

    // Builder
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private List<SdJwtClaim> claims;
        private String hashAlg;
        private JWSSigner signer;
        private String keyId;
        private List<DecoyClaim> decoyClaims;
        private boolean nestedDisclosures;
        private String jwsType;

        public Builder withClaims(List<SdJwtClaim> claims) {
            this.claims = claims;
            return this;
        }

        public Builder withDecoyClaims(List<DecoyClaim> decoyClaims) {
            this.decoyClaims = decoyClaims;
            return this;
        }

        public Builder withHashAlg(String hashAlg) {
            this.hashAlg = hashAlg;
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

        public Builder withNestedDisclosures(boolean nestedDisclosures) {
            this.nestedDisclosures = nestedDisclosures;
            return this;
        }

        public Builder withJwsType(String jwsType) {
            this.jwsType = jwsType;
            return this;
        }

        public IssuerSignedJWT build() {
            // Preinitialize hashAlg to sha-256 if not provided
            hashAlg = hashAlg == null ? "sha-256" : hashAlg;
            jwsType = jwsType == null ? "vc+sd-jwt" : jwsType;
            // send an empty lise if claims not set.
            claims = claims == null ? Collections.emptyList() : claims;
            decoyClaims = decoyClaims == null ? Collections.emptyList() : decoyClaims;
            if (signer != null) {
                return new IssuerSignedJWT(claims, decoyClaims, hashAlg, nestedDisclosures, signer, keyId, JWSAlgorithm.ES256, jwsType);
            } else {
                return new IssuerSignedJWT(claims, decoyClaims, hashAlg, nestedDisclosures);
            }
        }
    }

}
