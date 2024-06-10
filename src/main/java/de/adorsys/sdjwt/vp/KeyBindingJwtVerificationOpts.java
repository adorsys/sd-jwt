package de.adorsys.sdjwt.vp;

/**
 * Options for Key Binding JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class KeyBindingJwtVerificationOpts {
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

    private final boolean validateExpirationClaim;
    private final boolean validateNotBeforeClaim;

    public KeyBindingJwtVerificationOpts(
            boolean keyBindingRequired,
            int allowedMaxAge,
            String nonce,
            String aud,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim) {
        this.keyBindingRequired = keyBindingRequired;
        this.allowedMaxAge = allowedMaxAge;
        this.nonce = nonce;
        this.aud = aud;
        this.validateExpirationClaim = validateExpirationClaim;
        this.validateNotBeforeClaim = validateNotBeforeClaim;
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

    public boolean mustValidateExpirationClaim() {
        return validateExpirationClaim;
    }

    public boolean mustValidateNotBeforeClaim() {
        return validateNotBeforeClaim;
    }

    public static KeyBindingJwtVerificationOpts.Builder builder() {
        return new KeyBindingJwtVerificationOpts.Builder();
    }

    public static class Builder {
        private boolean keyBindingRequired = true;
        private int allowedMaxAge = 5 * 60;
        private String nonce;
        private String aud;
        private boolean validateExpirationClaim = true;
        private boolean validateNotBeforeClaim = true;

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

        public Builder withValidateExpirationClaim(boolean validateExpirationClaim) {
            this.validateExpirationClaim = validateExpirationClaim;
            return this;
        }

        public Builder withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
            this.validateNotBeforeClaim = validateNotBeforeClaim;
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
                    validateNotBeforeClaim
            );
        }
    }
}
