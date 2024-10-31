package de.adorsys.sdjwt.vp;

import de.adorsys.sdjwt.TimeClaimVerificationOpts;

/**
 * Options for Key Binding JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class KeyBindingJwtVerificationOpts extends TimeClaimVerificationOpts {

    public static final int DEFAULT_ALLOWED_MAX_AGE = 5 * 60;

    /**
     * Specifies the Verify's policy whether to check Key Binding
     */
    private final boolean keyBindingRequired;

    /**
     * Specifies the maximum age (in seconds) of an issued Key Binding
     */
    private final int allowedMaxAge;

    private final String nonce;
    private final String aud;

    public KeyBindingJwtVerificationOpts(
            boolean keyBindingRequired,
            int allowedMaxAge,
            String nonce,
            String aud,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim,
            int leewaySeconds) {
        super(validateExpirationClaim, validateNotBeforeClaim, leewaySeconds);
        this.keyBindingRequired = keyBindingRequired;
        this.allowedMaxAge = allowedMaxAge;
        this.nonce = nonce;
        this.aud = aud;
    }

    public boolean isKeyBindingRequired() {
        return keyBindingRequired;
    }

    public int getAllowedMaxAge() {
        return allowedMaxAge;
    }

    public String getNonce() {
        return nonce;
    }

    public String getAud() {
        return aud;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends TimeClaimVerificationOpts.Builder<Builder> {
        private boolean keyBindingRequired = true;
        private int allowedMaxAge = DEFAULT_ALLOWED_MAX_AGE;
        private String nonce;
        private String aud;

        public Builder withKeyBindingRequired(boolean keyBindingRequired) {
            this.keyBindingRequired = keyBindingRequired;
            return this;
        }

        public Builder withAllowedMaxAge(int allowedMaxAge) {
            this.allowedMaxAge = allowedMaxAge;
            return this;
        }

        public Builder withNonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder withAud(String aud) {
            this.aud = aud;
            return this;
        }

        public KeyBindingJwtVerificationOpts build() {
            if (keyBindingRequired && (aud == null || nonce == null || nonce.isEmpty())) {
                throw new IllegalArgumentException(
                        "Missing `nonce` and `aud` claims for replay protection"
                );
            }

            return new KeyBindingJwtVerificationOpts(
                    keyBindingRequired,
                    allowedMaxAge,
                    nonce,
                    aud,
                    validateExpirationClaim,
                    validateNotBeforeClaim,
                    leewaySeconds
            );
        }
    }
}
