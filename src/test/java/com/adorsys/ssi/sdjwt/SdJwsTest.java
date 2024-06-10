package com.adorsys.ssi.sdjwt;


import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

public class SdJwsTest {
    static TestSettings testSesstings = TestSettings.getInstance();

    private JsonNode createPayload() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("sub", "test");
        node.put("exp", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        node.put("name", "Test User");
        return node;
    }

    @Test
    public void testVerifySignature_Positive() throws Exception {
        SdJws sdJws = new SdJws(createPayload(), testSesstings.holderSigContext.signer, testSesstings.holderSigContext.keyId, JWSAlgorithm.ES256, "jwt") {
        };
        sdJws.verifySignature(testSesstings.holderVerifierContext.verifier);
    }

    @Test
    public void testVerifySignature_WrongPublicKey() {
        SdJws sdJws = new SdJws(createPayload(), testSesstings.holderSigContext.signer, testSesstings.holderSigContext.keyId, JWSAlgorithm.ES256, "jwt") {
        };
        assertThrows(JOSEException.class, () -> sdJws.verifySignature(testSesstings.issuerVerifierContext.verifier));
    }

    @Test
    public void testVerifyExpClaim_ExpiredJWT() {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("exp", Instant.now().minus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        assertThrows(SdJwtVerificationException.class, sdJws::verifyExpClaim);
    }

    @Test
    public void testVerifyExpClaim_Positive() throws Exception {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("exp", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        sdJws.verifyExpClaim();
    }

    @Test
    public void testVerifyNotBeforeClaim_Negative() {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("nbf", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        assertThrows(SdJwtVerificationException.class, sdJws::verifyNotBeforeClaim);
    }

    @Test
    public void testVerifyNotBeforeClaim_Positive() throws Exception {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("nbf", Instant.now().minus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        sdJws.verifyNotBeforeClaim();
    }

    @Test
    public void testPayloadJwsConstruction() {
        SdJws sdJws = new SdJws(createPayload()) {
        };
        assertNotNull(sdJws.getPayload());
    }

    @Test(expected = IllegalStateException.class)
    public void testUnsignedJwsConstruction() {
        SdJws sdJws = new SdJws(createPayload()) {
        };
        sdJws.toJws();
    }

    @Test
    public void testSignedJwsConstruction() {
        SdJws sdJws = new SdJws(createPayload(), testSesstings.holderSigContext.signer, testSesstings.holderSigContext.keyId, JWSAlgorithm.ES256, "jwt") {
        };
        assertNotNull(sdJws.toJws());
    }



    @Test
    public void testVerifyIssClaim_Negative() {
        List<String> allowedIssuers = List.of("issuer1@sdjwt.com", "issuer2@sdjwt.com");
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("iss", "unknown-issuer@sdjwt.com");
        SdJws sdJws = new SdJws(payload) {};
        var exception = assertThrows(SdJwtVerificationException.class, () -> sdJws.verifyIssClaim(allowedIssuers));
        assertEquals("Unknown 'iss' claim value: unknown-issuer@sdjwt.com", exception.getMessage());
    }

    @Test
    public void testVerifyIssClaim_Positive() throws SdJwtVerificationException {
        List<String> allowedIssuers = List.of("issuer1@sdjwt.com", "issuer2@sdjwt.com");
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("iss", "issuer1@sdjwt.com");
        SdJws sdJws = new SdJws(payload) {};
        sdJws.verifyIssClaim(allowedIssuers);
    }

    @Test
    public void testVerifyVctClaim_Negative() {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("vct", "IdentityCredential");
        SdJws sdJws = new SdJws(payload) {};
        var exception = assertThrows(SdJwtVerificationException.class, () -> sdJws.verifyVctClaim(List.of("PassportCredential")));
        assertEquals("Unknown 'vct' claim value: IdentityCredential", exception.getMessage());
    }

    @Test
    public void testVerifyVctClaim_Positive() throws SdJwtVerificationException {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("vct", "IdentityCredential");
        SdJws sdJws = new SdJws(payload) {};
        sdJws.verifyVctClaim(List.of("IdentityCredential".toLowerCase()));
    }
}