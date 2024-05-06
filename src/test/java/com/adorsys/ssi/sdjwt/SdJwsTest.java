package com.adorsys.ssi.sdjwt;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import org.junit.Test;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

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
    public void testVerifySignature_WrongPublicKey() throws Exception {
        SdJws sdJws = new SdJws(createPayload(), testSesstings.holderSigContext.signer, testSesstings.holderSigContext.keyId, JWSAlgorithm.ES256, "jwt") {
        };
        assertThrows(JOSEException.class, () -> sdJws.verifySignature(testSesstings.issuerVerifierContext.verifier));
    }

    @Test
    public void testVerifyExpClaim_ExpiredJWT() throws JOSEException {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("exp", Instant.now().minus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        assertThrows(JOSEException.class, sdJws::verifyExpClaim);
    }

    @Test
    public void testVerifyExpClaim_Positive() throws JOSEException {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("exp", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        sdJws.verifyExpClaim();
    }

    @Test
    public void testVerifyNotBeforeClaim_Negative() throws JOSEException {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("nbf", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        SdJws sdJws = new SdJws(payload) {
        };
        assertThrows(JOSEException.class, sdJws::verifyNotBeforeClaim);
    }

    @Test
    public void testVerifyNotBeforeClaim_Positive() throws JOSEException {
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
    public void testSignedJwsConstruction() throws JOSEException {
        SdJws sdJws = new SdJws(createPayload(), testSesstings.holderSigContext.signer, testSesstings.holderSigContext.keyId, JWSAlgorithm.ES256, "jwt") {
        };
        assertNotNull(sdJws.toJws());
    }
}