
package de.adorsys.sdjwt;

import de.adorsys.sdjwt.exception.SdJwtVerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

    public JsonNode getHeader() {
        return SdJwtUtils.mapper.valueToTree(this.signedJwt.getHeader().toJSONObject());
    }

    public void verifySignature(JWSVerifier verifier) throws JOSEException {
        if (!this.signedJwt.verify(verifier)) {
            throw new JOSEException("Invalid JWS signature");
        }
    }

    public void verifyIssuedAtClaim() throws SdJwtVerificationException {
        long now = Instant.now().getEpochSecond();
        long iat = SdJwtUtils.readTimeClaim(payload, "iat");

        if (now < iat) {
            throw new SdJwtVerificationException("jwt issued in the future");
        }
    }

    public void verifyExpClaim() throws SdJwtVerificationException {
        long now = Instant.now().getEpochSecond();
        long exp = SdJwtUtils.readTimeClaim(payload, "exp");

        if (now >= exp) {
            throw new SdJwtVerificationException("jwt has expired");
        }
    }

    public void verifyNotBeforeClaim() throws SdJwtVerificationException {
        long now = Instant.now().getEpochSecond();
        long nbf = SdJwtUtils.readTimeClaim(payload, "nbf");

        if (now < nbf) {
            throw new SdJwtVerificationException("jwt not valid yet");
        }
    }

    /**
     * Verifies that SD-JWT was issued by one of the provided issuers. Verification is case-insensitive
     * @param issuers List of trusted issuers
     */
    public void verifyIssClaim(List<String> issuers) throws SdJwtVerificationException {
        verifyClaimAgainstTrustedValues(issuers, "iss");
    }

    /**
     * Verifies that SD-JWT vct claim matches the expected one. Verification is case-insensitive
     * @param vcts list of supported verifiable credential types
     */
    public void verifyVctClaim(List<String> vcts) throws SdJwtVerificationException  {
        verifyClaimAgainstTrustedValues(vcts, "vct");
    }

    private void verifyClaimAgainstTrustedValues(List<String> trustedValues, String claimName)
            throws SdJwtVerificationException {
        String claimValue = SdJwtUtils.readClaim(payload, claimName);

        List<String> normalizedValues = new ArrayList<>();
        for (String value : trustedValues) {
            normalizedValues.add(value.toLowerCase());
        }

        if (!normalizedValues.contains(claimValue.toLowerCase())) {
            throw new SdJwtVerificationException(String.format("Unknown '%s' claim value: %s", claimName, claimValue));
        }
    }

    private static JWSObject parse(String jwsString) throws ParseException {
        return JWSObject.parse(Objects.requireNonNull(jwsString, "jwsString must not be null"));
    }

    private static JsonNode readPayload(JWSObject jwsInput) throws ParseException, IOException {
        return SdJwtUtils.mapper.readValue(jwsInput.getParsedParts()[1].decode(), JsonNode.class);
    }
}
