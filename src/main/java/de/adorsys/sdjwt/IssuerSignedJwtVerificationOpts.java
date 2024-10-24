package de.adorsys.sdjwt;

import com.nimbusds.jose.JWSVerifier;

/**
 * Options for Issuer-signed JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class IssuerSignedJwtVerificationOpts {
    private final JWSVerifier verifier;

    private final boolean validateExpirationClaim;
    private final boolean validateNotBeforeClaim;

    /**
     * Tolerance window to account for clock skew when checking time claims
     */
    private final int leewaySeconds;

    public IssuerSignedJwtVerificationOpts(
            JWSVerifier verifier,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim,
            int leewaySeconds) {
        this.verifier = verifier;
        this.validateExpirationClaim = validateExpirationClaim;
        this.validateNotBeforeClaim = validateNotBeforeClaim;
        this.leewaySeconds = leewaySeconds;
    }

    public JWSVerifier getVerifier() {
        return verifier;
    }

    public boolean mustValidateExpirationClaim() {
        return validateExpirationClaim;
    }

    public boolean mustValidateNotBeforeClaim() {
        return validateNotBeforeClaim;
    }

    public int getLeewaySeconds() {
        return leewaySeconds;
    }

    public static IssuerSignedJwtVerificationOpts.Builder builder() {
        return new IssuerSignedJwtVerificationOpts.Builder();
    }

    public static class Builder {
        private JWSVerifier verifier;
        private boolean validateExpirationClaim = true;
        private boolean validateNotBeforeClaim = true;
        private int leewaySeconds = 10;

        public Builder withVerifier(JWSVerifier verifier) {
            this.verifier = verifier;
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

        public Builder withLeewaySeconds(int leewaySeconds) {
            this.leewaySeconds = leewaySeconds;
            return this;
        }

        public IssuerSignedJwtVerificationOpts build() {
            return new IssuerSignedJwtVerificationOpts(
                    verifier,
                    validateExpirationClaim,
                    validateNotBeforeClaim,
                    leewaySeconds
            );
        }
    }
}
