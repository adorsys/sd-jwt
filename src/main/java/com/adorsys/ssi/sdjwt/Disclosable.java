
package com.adorsys.ssi.sdjwt;

import java.util.Objects;

import org.keycloak.jose.jws.crypto.HashUtils;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Handles undisclosed claims and array elements, providing functionality
 * to generate disclosure digests from Base64Url encoded strings.
 * 
 * Hiding claims and array elements occurs by including their digests
 * instead of plaintext in the signed verifiable credential.
 * 
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 * 
 */
public abstract class Disclosable {
    private final SdJwtSalt salt;

    /**
     * Returns the array of undisclosed value, for
     * encoding (disclosure string) and hashing (_sd digest array in the VC).
     */
    abstract Object[] toArray();

    protected Disclosable(SdJwtSalt salt) {
        this.salt = Objects.requireNonNull(salt, "Disclosure always requires a salt must not be null");
    }

    public SdJwtSalt getSalt() {
        return salt;
    }

    public String getSaltAsString() {
        return salt.toString();
    }

    public String toJson() {
        try {
            return SdJwtUtils.printJsonArray(toArray());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public String getDisclosureString() {
        String json = toJson();
        return SdJwtUtils.encodeNoPad(json.getBytes());
    }

    public String getDisclosureDigest(String hashAlg) {
        return SdJwtUtils.encodeNoPad(HashUtils.hash(hashAlg, getDisclosureString().getBytes()));
    }

    @Override
    public String toString() {
        return getDisclosureString();
    }
}
