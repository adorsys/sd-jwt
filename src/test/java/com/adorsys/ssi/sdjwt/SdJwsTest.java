package com.adorsys.ssi.sdjwt;


import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

import org.keycloak.common.VerificationException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;

public class SdJwsTest {
    private SdJws sdJws;
    private JsonNode payload;

    @Before
    public void setUp() {
        payload = createPayload();
        sdJws = new SdJws(payload);
    }

    private JsonNode createPayload() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("sub", "test");
        node.put("exp", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        node.put("name", "Test User");
        return node;
    }

    @Test
    public void testToJws() {
        assertThrows(IllegalStateException.class, () -> sdJws.toJws());
    }

    @Test
    public void testGetPayload() {
        assertEquals(payload, sdJws.getPayload());
    }

    @Test
    public void testGetJwsString() {
        assertThrows(NullPointerException.class, () -> sdJws.getJwsString());
    }

    @Test
    public void testVerifySignature() throws Exception {
        SignatureSignerContext signatureSignerContext = TestSettings.getInstance().holderSigContext;
        SignatureVerifierContext signatureVerifierContext = TestSettings.getInstance().holderVerifierContext;

        sdJws = new SdJws(payload, signatureSignerContext, "jwt");

        JWSInput jwsInput = new JWSInput(sdJws.getJwsString());

        assertEquals(jwsInput.getEncodedSignatureInput(), sdJws.getJwsInput().getEncodedSignatureInput());
        assertEquals(Arrays.toString(jwsInput.getSignature()), Arrays.toString(sdJws.getJwsInput().getSignature()));

        sdJws.verifySignature(signatureVerifierContext);

        assertThrows(VerificationException.class, () -> sdJws.verifySignature(TestSettings.getInstance().issuerVerifierContext));
    }

    @Test
    public void testVerifyExpClaim() throws VerificationException {
        sdJws = new SdJws(createPayload());
        ((ObjectNode) payload).put("exp", Instant.now().minus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        sdJws = new SdJws(payload);
        assertThrows(VerificationException.class, () -> sdJws.verifyExpClaim());

        payload = createPayload();
        ((ObjectNode) payload).put("exp", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        sdJws = new SdJws(payload);
        sdJws.verifyExpClaim();
    }

    @Test
    public void testVerifyNotBeforeClaim() throws VerificationException {
        JsonNode payload = createPayload();
        ((ObjectNode) payload).put("nbf", Instant.now().plus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        sdJws = new SdJws(payload);
        assertThrows(VerificationException.class, () -> sdJws.verifyNotBeforeClaim());

        payload = createPayload();
        ((ObjectNode) payload).put("nbf", Instant.now().minus(1, TimeUnit.HOURS.toChronoUnit()).getEpochSecond());
        sdJws = new SdJws(payload);
        sdJws.verifyNotBeforeClaim();
    }
}