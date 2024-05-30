
package com.adorsys.ssi.sdjwt.sdjwtvp;

import com.adorsys.ssi.sdjwt.DisclosureRedList;
import com.adorsys.ssi.sdjwt.DisclosureSpec;
import com.adorsys.ssi.sdjwt.SdJwt;
import com.adorsys.ssi.sdjwt.SdJwtVerificationOptions;
import com.adorsys.ssi.sdjwt.TestSettings;
import com.adorsys.ssi.sdjwt.TestUtils;
import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.adorsys.ssi.sdjwt.vp.SdJwtVP;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSSigner;
import org.junit.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVpVerificationTest {
    static ObjectMapper mapper = new ObjectMapper();
    static TestSettings testSettings = TestSettings.getInstance();

    @Test
    public void settingsTest() {
        JWSSigner issuerSignerContext = testSettings.issuerSigContext.signer;
        assertNotNull(issuerSignerContext);
    }

    @Test
    public void testVerif_s20_1_sdjwt_with_kb() throws SdJwtVerificationException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s20.1-sdjwt+kb.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        sdJwtVP.verify(defaultVerificationOptions()
                .withValidateIssuedAtClaim(true)
                .build());
    }

    private SdJwtVerificationOptions.Builder defaultVerificationOptions() {
        return SdJwtVerificationOptions.builder()
                .withVerifier(testSettings.issuerVerifierContext.verifier)
                .withValidateIssuedAtClaim(false)
                .withValidateExpirationClaim(false)
                .withValidateNotBeforeClaim(false);
    }
}
