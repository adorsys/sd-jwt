
package com.adorsys.ssi.sdjwt.sdjwtvp;

import com.adorsys.ssi.sdjwt.IssuerSignedJwtVerificationOpts;
import com.adorsys.ssi.sdjwt.TestSettings;
import com.adorsys.ssi.sdjwt.TestUtils;
import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
import com.adorsys.ssi.sdjwt.vp.KeyBindingJwtVerificationOpts;
import com.adorsys.ssi.sdjwt.vp.SdJwtVP;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVPVerificationTest {
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

        sdJwtVP.verify(
                defaultIssuerSignedJwtVerificationOpts().build(),
                defaultKeyBindingJwtVerificationOpts().build()
        );
    }

    @Test
    public void testVerifKeyBindingNotRequired() throws SdJwtVerificationException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        sdJwtVP.verify(
                defaultIssuerSignedJwtVerificationOpts().build(),
                defaultKeyBindingJwtVerificationOpts()
                        .withKeyBindingRequired(false)
                        .build()
        );
    }

    @Test
    public void testShouldFail_IfExtraDisclosureWithNoDigest() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // One disclosure has no digest throughout Issuer-signed JWT
                "sdjwt/s20.6-sdjwt+kb--disclosure-with-no-digest.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "At least one disclosure is not protected by digest",
                null
        );
    }

    @Test
    public void testShouldFail_IfKeyBindingRequiredAndMissing() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // This sd-jwt has no key binding jwt
                "sdjwt/s6.2-presented-sdjwtvp.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withKeyBindingRequired(true)
                        .build(),
                "Missing Key Binding JWT",
                null
        );
    }

    @Test
    public void testShouldFail_IfKeyBindingJwtSignatureInvalid() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // Messed up with the kb signature
                "sdjwt/s20.1-sdjwt+kb--wrong-kb-signature.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT invalid",
                "Invalid JWS signature"
        );
    }

    @Test
    public void testShouldFail_IfNoCnfClaim() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // This test vector has no cnf claim in Issuer-signed JWT
                "sdjwt/s20.2-sdjwt+kb--no-cnf-claim.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "No cnf claim in Issuer-signed JWT for key binding",
                null
        );
    }

    @Test
    public void testShouldFail_IfWrongKbTyp() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // Key Binding JWT's header: {"kid": "holder", "typ": "unexpected",  "alg": "ES256"}
                "sdjwt/s20.3-sdjwt+kb--wrong-kb-typ.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key Binding JWT is not of declared typ kb+jwt",
                null
        );
    }

    @Test
    public void testShouldFail_IfReplayChecksFail_Nonce() throws SdJwtVerificationException {
        testShouldFailGeneric(
                "sdjwt/s20.1-sdjwt+kb.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withNonce("abcd") // kb's nonce is "1234567890"
                        .build(),
                "Key binding JWT: Unexpected `nonce` value",
                null
        );
    }

    @Test
    public void testShouldFail_IfReplayChecksFail_Aud() throws SdJwtVerificationException {
        testShouldFailGeneric(
                "sdjwt/s20.1-sdjwt+kb.txt",
                defaultKeyBindingJwtVerificationOpts()
                        .withAud("abcd") // kb's aud is "https://verifier.example.org"
                        .build(),
                "Key binding JWT: Unexpected `aud` value",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbSdHashWrongFormat() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // Key Binding JWT's sd_hash is not a string
                "sdjwt/s20.4-sdjwt+kb--sd_hash-not-string.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT: Claim `sd_hash` missing or not a string",
                null
        );
    }

    @Test
    public void testShouldFail_IfKbSdHashInvalid() throws SdJwtVerificationException {
        testShouldFailGeneric(
                // Key Binding JWT's sd_hash is invalid
                "sdjwt/s20.5-sdjwt+kb--wrong-sd_hash.txt",
                defaultKeyBindingJwtVerificationOpts().build(),
                "Key binding JWT: Invalid `sd_hash` digest",
                null
        );
    }

    private void testShouldFailGeneric(
            String testFilePath,
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts,
            String exceptionMessage,
            String exceptionCauseMessage
    ) {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), testFilePath);
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        var exception = assertThrows(
                SdJwtVerificationException.class,
                () -> sdJwtVP.verify(
                        defaultIssuerSignedJwtVerificationOpts().build(),
                        keyBindingJwtVerificationOpts
                )
        );

        assertEquals(exceptionMessage, exception.getMessage());
        if (exceptionCauseMessage != null) {
            assertEquals(exceptionCauseMessage, exception.getCause().getMessage());
        }
    }

    private IssuerSignedJwtVerificationOpts.Builder defaultIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withVerifier(testSettings.issuerVerifierContext.verifier)
                .withValidateIssuedAtClaim(true)
                .withValidateNotBeforeClaim(false);
    }

    private KeyBindingJwtVerificationOpts.Builder defaultKeyBindingJwtVerificationOpts() {
        return KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withNonce("1234567890")
                .withAud("https://verifier.example.org")
                .withValidateExpirationClaim(false)
                .withValidateNotBeforeClaim(false);
    }
}
