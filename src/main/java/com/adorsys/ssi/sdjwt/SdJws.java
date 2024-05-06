
package com.adorsys.ssi.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Objects;

/**
 * Handle jws, either the issuer jwt or the holder key binding jwt.
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public abstract class SdJws {
    private final JWSObject signedJwt;

    private final String jwsString;
    private final JsonNode payload;

    public String toJws() {
        if (jwsString == null) {
            throw new IllegalStateException("JWS not yet signed");
        }
        return jwsString;
    }

    public JsonNode getPayload() {
        return payload;
    }

    // Constructor for unsigned JWS
    protected SdJws(JsonNode payload) {
        this.payload = payload;
        this.signedJwt = null;
        this.jwsString = null;
    }

    // Constructor from jws string with all parts
    protected SdJws(String jwsString) {
        try {
            this.jwsString = jwsString;
            this.signedJwt = parse(jwsString);
            this.payload = readPayload(signedJwt);
        } catch (ParseException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Constructor for signed JWS
    protected SdJws(JsonNode payload, JWSObject signedJwt) {
        this.payload = payload;
        this.signedJwt = signedJwt;
        this.jwsString = signedJwt.serialize();
    }

    protected SdJws(JsonNode payload, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        this.payload = payload;
        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm).type(new JOSEObjectType(jwsType)).keyID(keyId).build();
        this.signedJwt = new JWSObject(header, new Payload(Base64URL.encode(payload.toString())));
        try {
            this.signedJwt.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        this.jwsString= signedJwt.serialize();
    }
    protected SdJws(Base64URL payloadBase64Url, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        try {
            this.payload = SdJwtUtils.mapper.readTree(payloadBase64Url.decode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm).type(new JOSEObjectType(jwsType)).keyID(keyId).build();
        this.signedJwt = new JWSObject(header, new Payload(payloadBase64Url));
        try {
            this.signedJwt.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        this.jwsString= signedJwt.serialize();
    }

    public void verifySignature(JWSVerifier verifier) throws JOSEException {
        if (!this.signedJwt.verify(verifier)) {
            throw new JOSEException("Invalid JWS signature");
        }
    }

    public void verifyExpClaim() throws JOSEException {
        verifyTimeClaim("exp", "jwt has expired");
    }

    public void verifyNotBeforeClaim() throws JOSEException {
        verifyTimeClaim("nbf", "jwt not valid yet");
    }

    private void verifyTimeClaim(String claimName, String errorMessage) throws JOSEException {
        JsonNode claim = payload.get(claimName);
        if (claim == null || !claim.isNumber()) {
            throw new JOSEException("Missing or invalid '" + claimName + "' claim");
        }

        long claimTime = claim.asLong();
        long currentTime = Instant.now().getEpochSecond();
        if (("exp".equals(claimName) && currentTime >= claimTime) || ("nbf".equals(claimName) && currentTime < claimTime)) {
            throw new JOSEException(errorMessage);
        }
    }

    private static JWSObject parse(String jwsString) throws ParseException {
        return JWSObject.parse(Objects.requireNonNull(jwsString, "jwsString must not be null"));
    }

    private static JsonNode readPayload(JWSObject jwsInput) throws ParseException, IOException {
        return SdJwtUtils.mapper.readValue(jwsInput.getParsedParts()[1].decode(), JsonNode.class);
    }
}
