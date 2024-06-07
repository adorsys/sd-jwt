
package com.adorsys.ssi.sdjwt.vp;

import com.adorsys.ssi.sdjwt.SdJws;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class KeyBindingJWT extends SdJws {

    public static final String TYP = "kb+jwt";

    public KeyBindingJWT(JsonNode payload, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        super(payload, signer, keyId, jwsAlgorithm, jwsType);
    }

    public static KeyBindingJWT of(String jwsString) {
        return new KeyBindingJWT(jwsString);
    }

    public static KeyBindingJWT from(JsonNode payload, JWSSigner signer, String keyId, JWSAlgorithm jwsAlgorithm, String jwsType) {
        return new KeyBindingJWT(payload, signer, keyId, jwsAlgorithm, jwsType);
    }

    private KeyBindingJWT(JsonNode payload, JWSObject jwsInput) {
        super(payload, jwsInput);
    }

    private KeyBindingJWT(String jwsString) {
        super(jwsString);
    }
}
