package de.adorsys.sdjwt;

import com.fasterxml.jackson.databind.node.ObjectNode;
import de.adorsys.sdjwt.exception.SdJwtVerificationException;
import org.junit.Test;

import static de.adorsys.sdjwt.TimeClaimVerifier.CLAIM_NAME_EXP;
import static de.adorsys.sdjwt.TimeClaimVerifier.CLAIM_NAME_NBF;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class TimeClaimVerifierTest {

    // 60 seconds of leeway
    private final TimeClaimVerifier timeClaimVerifier = new FixedTimeClaimVerifier(60);

    private static final long CURRENT_TIMESTAMP = 1609459200L; // Fixed timestamp: 2021-01-01 00:00:00 UTC

    static class FixedTimeClaimVerifier extends TimeClaimVerifier {

        public FixedTimeClaimVerifier(int leewaySeconds) {
            super(leewaySeconds);
        }

        @Override
        public long currentTimestamp() {
            return CURRENT_TIMESTAMP;
        }
    }

    @Test
    public void testVerifyExpClaimExpired() {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_EXP, CURRENT_TIMESTAMP - 100); // Expired 100 seconds ago

        var exception = assertThrows(SdJwtVerificationException.class,
                () -> timeClaimVerifier.verifyExpClaim(payload));

        assertEquals("JWT has expired", exception.getMessage());
    }

    @Test
    public void testVerifyExpClaimValid() throws SdJwtVerificationException {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_EXP, CURRENT_TIMESTAMP + 100); // Expires 100 seconds in the future

        timeClaimVerifier.verifyExpClaim(payload);
    }

    @Test
    public void testVerifyExpClaimEdge() throws SdJwtVerificationException {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_EXP, CURRENT_TIMESTAMP - 59); // 59 seconds ago, within the 60 second leeway

        // No exception expected for JWT expiring within leeway
        timeClaimVerifier.verifyExpClaim(payload);
    }

    @Test
    public void testVerifyNotBeforeClaimNotYetValid() {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_NBF, CURRENT_TIMESTAMP + 100); // Not valid for another 100 seconds

        var exception = assertThrows(SdJwtVerificationException.class,
                () -> timeClaimVerifier.verifyNotBeforeClaim(payload));

        assertEquals("JWT is not yet valid", exception.getMessage());
    }

    @Test
    public void testVerifyNotBeforeClaimValid() throws SdJwtVerificationException {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_NBF, CURRENT_TIMESTAMP - 100); // Valid since 100 seconds ago

        timeClaimVerifier.verifyNotBeforeClaim(payload);
    }

    // Test for verifyNotBeforeClaim (edge case: valid exactly at current time with leeway)
    @Test
    public void testVerifyNotBeforeClaimEdge() throws SdJwtVerificationException {
        ObjectNode payload = SdJwtUtils.mapper.createObjectNode();
        payload.put(CLAIM_NAME_NBF, CURRENT_TIMESTAMP + 59); // 59 seconds in the future, within the 60 second leeway

        // No exception expected for JWT becoming valid within leeway
        timeClaimVerifier.verifyNotBeforeClaim(payload);
    }

    @Test
    public void instantiationShouldFailIfLeewayNegative() {
        var exception = assertThrows(IllegalArgumentException.class,
                () -> new TimeClaimVerifier(-1));

        assertEquals("Leeway seconds cannot be negative", exception.getMessage());
    }
}
