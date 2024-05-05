
package com.adorsys.ssi.sdjwt;

import java.util.Objects;

/**
 * Handles hash production for a decoy entry from the given salt.
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public abstract class DecoyEntry {
    private final SdJwtSalt salt;

    protected DecoyEntry(SdJwtSalt salt) {
        this.salt = Objects.requireNonNull(salt, "DecoyEntry always requires a non null salt");
    }

    public SdJwtSalt getSalt() {
        return salt;
    }

    public String getDisclosureDigest(String hashAlg) {
        return SdJwtUtils.encodeNoPad(SdJwtUtils.hash(salt.toString().getBytes(), hashAlg));
    }
}
