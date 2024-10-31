package de.adorsys.sdjwt;

import com.nimbusds.jose.JWSVerifier;

/**
 * Options for Issuer-signed JWT verification.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class IssuerSignedJwtVerificationOpts extends TimeClaimVerificationOpts {

    private final JWSVerifier verifier;

    public IssuerSignedJwtVerificationOpts(
            JWSVerifier verifier,
            boolean validateExpirationClaim,
            boolean validateNotBeforeClaim,
            int leewaySeconds) {
        super(validateExpirationClaim, validateNotBeforeClaim, leewaySeconds);
        this.verifier = verifier;
    }

    public JWSVerifier getVerifier() {
        return verifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends TimeClaimVerificationOpts.Builder<Builder> {
        private JWSVerifier verifier;

        public Builder withVerifier(JWSVerifier verifier) {
            this.verifier = verifier;
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
