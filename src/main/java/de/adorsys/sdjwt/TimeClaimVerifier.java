package de.adorsys.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import de.adorsys.sdjwt.exception.SdJwtVerificationException;

import java.time.Instant;

/**
 * Module for checking the validity of JWT time claims
 */
public class TimeClaimVerifier {

    public static final String CLAIM_NAME_EXP = "exp";
    public static final String CLAIM_NAME_NBF = "nbf";

    /**
     * Tolerance window to account for clock skew
     */
    private final int leewaySeconds;

    public TimeClaimVerifier(int leewaySeconds) {
        if (leewaySeconds < 0) {
            throw new IllegalArgumentException("Leeway seconds cannot be negative");
        }

        this.leewaySeconds = leewaySeconds;
    }

    /**
     * Validates that JWT has not expired
     *
     * @param jwtPayload the JWT's payload
     */
    public void verifyExpClaim(JsonNode jwtPayload) throws SdJwtVerificationException {
        long exp = SdJwtUtils.readTimeClaim(jwtPayload, CLAIM_NAME_EXP);

        if ((currentTimestamp() - leewaySeconds) >= exp) {
            throw new SdJwtVerificationException("JWT has expired");
        }
    }

    /**
     * Validates that JWT can yet be processed
     *
     * @param jwtPayload the JWT's payload
     */
    public void verifyNotBeforeClaim(JsonNode jwtPayload) throws SdJwtVerificationException {
        long nbf = SdJwtUtils.readTimeClaim(jwtPayload, CLAIM_NAME_NBF);

        if ((currentTimestamp() + leewaySeconds) < nbf) {
            throw new SdJwtVerificationException("JWT is not yet valid");
        }
    }

    /**
     * Returns current timestamp in seconds.
     */
    public long currentTimestamp() {
        return Instant.now().getEpochSecond();
    }
}
