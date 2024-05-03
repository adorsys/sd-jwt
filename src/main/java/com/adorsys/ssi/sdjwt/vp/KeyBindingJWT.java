
package com.adorsys.ssi.sdjwt.vp;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSInput;
import com.adorsys.ssi.sdjwt.SdJws;

/**
 * 
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 * 
 */
public class KeyBindingJWT extends SdJws {

    public static KeyBindingJWT of(String jwsString) {
        return new KeyBindingJWT(jwsString);
    }

    public static KeyBindingJWT from(JsonNode payload, SignatureSignerContext signer, String jwsType) {
        JWSInput jwsInput = sign(payload, signer, jwsType);
        return new KeyBindingJWT(payload, jwsInput);
    }

    private KeyBindingJWT(JsonNode payload, JWSInput jwsInput) {
        super(payload, jwsInput);
    }

    private KeyBindingJWT(String jwsString) {
        super(jwsString);
    }
}
