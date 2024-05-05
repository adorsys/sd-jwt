
package com.adorsys.ssi.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import java.text.ParseException;

/**
 * Import test-settings from:
 * <a href="https://github.com/openwallet-foundation-labs/sd-jwt-python/blob/main/src/sd_jwt/utils/demo_settings.yml">
 *     open wallet foundation labs</a>
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class TestSettings {
    public final SignatureSignerContext holderSigContext;
    public final SignatureSignerContext issuerSigContext;
    public final SignatureVerifierContext holderVerifierContext;
    public final SignatureVerifierContext issuerVerifierContext;
    public final JWSAlgorithm jwsAlgorithm;

    private static TestSettings instance = null;

    public static TestSettings getInstance() {
        if (instance == null) {
            try {
                instance = new TestSettings();
            } catch (ParseException | JOSEException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }

    private TestSettings() throws ParseException, JOSEException {
        // Load keys from your configuration file or generate if necessary
        JsonNode testSettings = TestUtils.readClaimSet(getClass(), "sdjwt/test-settings.json"); // Or adapt this to your method of reading settings
        JsonNode keySettings = testSettings.get("key_settings");

        ECKey holderKey = loadOrCreateECKey(keySettings, "holder_key");
        holderSigContext = new SignatureSignerContext(new ECDSASigner(holderKey.toECPrivateKey()), holderKey.getKeyID());
        holderVerifierContext = new SignatureVerifierContext(new ECDSAVerifier(holderKey.toECPublicKey()));

        ECKey issuerKey = loadOrCreateECKey(keySettings, "issuer_key");
        issuerSigContext = new SignatureSignerContext(new ECDSASigner(issuerKey.toECPrivateKey()), issuerKey.getKeyID());
        issuerVerifierContext = new SignatureVerifierContext(new ECDSAVerifier(issuerKey.toECPublicKey()));

        jwsAlgorithm = JWSAlgorithm.parse(testSettings.get("jwsAlgorithm").asText());
    }

    private ECKey loadOrCreateECKey(JsonNode keySettings, String keyName) throws ParseException, JOSEException {
        // private constructor
        JsonNode keySetting = keySettings.get(keyName);
        return parseJwk(keySetting).toECKey(); // Where 'keyData' is your JWK
    }

    public static JWSVerifier verifierContextFrom(JsonNode keyData, String algorithm) throws ParseException, JOSEException {
        return new ECDSAVerifier(parseJwk(keyData).toECKey().toECPublicKey());
    }

    private static JWK parseJwk(JsonNode keySetting) throws ParseException {
        JsonNode jwk = keySetting.get("jwk");
        if(jwk!=null){
            keySetting = jwk;
        }
        return JWK.parse(keySetting.toString());
    }

    public static class SignatureSignerContext {
        public final JWSSigner signer;
        public final String keyId;

        SignatureSignerContext(JWSSigner signer, String keyId) {
            this.signer = signer;
            this.keyId = keyId;
        }
    }
    public static class SignatureVerifierContext {
        public final JWSVerifier verifier;

        SignatureVerifierContext(JWSVerifier verifier) {
            this.verifier = verifier;
        }
    }
}
