package com.adorsys.ssi.sdjwt;

import com.nimbusds.jose.JWSVerifier;

/**
 * Options for Issuer-signed JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class IssuerSignedJwtVerificationOpts {
    private final JWSVerifier verifier;
    private final boolean validateIssuedAtClaim;
    private final boolean validateExpirationClaim;
    private final boolean validateNotBeforeClaim;

    public IssuerSignedJwtVerificationOpts(
            JWSVerifier verifier,
            boolean validateIssuedAtClaim,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim) {
        this.verifier = verifier;
        this.validateIssuedAtClaim = validateIssuedAtClaim;
        this.validateExpirationClaim = validateExpirationClaim;
        this.validateNotBeforeClaim = validateNotBeforeClaim;
    }

    public JWSVerifier getVerifier() {
        return verifier;
    }

    public boolean mustValidateIssuedAtClaim() {
        return validateIssuedAtClaim;
    }

    public boolean mustValidateExpirationClaim() {
        return validateExpirationClaim;
    }

    public boolean mustValidateNotBeforeClaim() {
        return validateNotBeforeClaim;
    }

    public static IssuerSignedJwtVerificationOpts.Builder builder() {
        return new IssuerSignedJwtVerificationOpts.Builder();
    }

    public static class Builder {
        private JWSVerifier verifier;
        private boolean validateIssuedAtClaim;
        private boolean validateExpirationClaim = true;
        private boolean validateNotBeforeClaim = true;

        public Builder withVerifier(JWSVerifier verifier) {
            this.verifier = verifier;
            return this;
        }

        public Builder withValidateIssuedAtClaim(boolean validateIssuedAtClaim) {
            this.validateIssuedAtClaim = validateIssuedAtClaim;
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

        public IssuerSignedJwtVerificationOpts build() {
            return new IssuerSignedJwtVerificationOpts(
                    verifier,
                    validateIssuedAtClaim,
                    validateExpirationClaim,
                    validateNotBeforeClaim
            );
        }
    }
}
