package de.adorsys.sdjwt;

/**
 * Options for validating common time claims during SD-JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TimeClaimVerificationOpts {

    /**
     * Tolerance window to account for clock skew when checking time claims
     */
    public static final int DEFAULT_LEEWAY_SECONDS = 10;

    private final boolean validateExpirationClaim;
    private final boolean validateNotBeforeClaim;
    private final int leewaySeconds;

    public TimeClaimVerificationOpts(
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim,
            int leewaySeconds) {
        this.validateExpirationClaim = validateExpirationClaim;
        this.validateNotBeforeClaim = validateNotBeforeClaim;
        this.leewaySeconds = leewaySeconds;
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

    public static <T extends Builder<T>> Builder<T> builder() {
        return new Builder<>();
    }

    public static class Builder<T extends Builder<T>> {

        protected boolean validateExpirationClaim = true;
        protected boolean validateNotBeforeClaim = true;
        protected int leewaySeconds = DEFAULT_LEEWAY_SECONDS;

        @SuppressWarnings("unchecked")
        public T withValidateExpirationClaim(boolean validateExpirationClaim) {
            this.validateExpirationClaim = validateExpirationClaim;
            return (T) this;
        }

        @SuppressWarnings("unchecked")
        public T withValidateNotBeforeClaim(boolean validateNotBeforeClaim) {
            this.validateNotBeforeClaim = validateNotBeforeClaim;
            return (T) this;
        }

        @SuppressWarnings("unchecked")
        public T withLeewaySeconds(int leewaySeconds) {
            this.leewaySeconds = leewaySeconds;
            return (T) this;
        }

        public TimeClaimVerificationOpts build() {
            return new TimeClaimVerificationOpts(
                    validateExpirationClaim,
                    validateNotBeforeClaim,
                    leewaySeconds
            );
        }
    }
}
