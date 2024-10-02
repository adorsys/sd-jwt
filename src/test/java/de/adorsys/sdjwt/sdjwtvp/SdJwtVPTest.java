
package de.adorsys.sdjwt.sdjwtvp;

import de.adorsys.sdjwt.*;
import de.adorsys.sdjwt.vp.KeyBindingJWT;
import de.adorsys.sdjwt.vp.SdJwtVP;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import org.junit.Test;

import java.text.ParseException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;


/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class SdJwtVPTest {
    static TestSettings testSettings = TestSettings.getInstance();
    // Additional tests can be written to cover edge cases, error conditions,
    // and any other functionality specific to the SdJwt class.
    @Test
    public void testIssuerSignedJWTWithUndisclosedClaims3_3() {
        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "2GLC42sKQveCfGfryNRN9w")
                .withUndisclosedClaim("family_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("email", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("phone_number", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withUndisclosedClaim("address", "Qg_O64zqAxe412a108iroA")
                .withUndisclosedClaim("birthdate", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("is_over_18", "Pc33JM2LchcU_lHggv_ufQ")
                .withUndisclosedClaim("is_over_21", "G02NSrQfjFXQ7Io09syajA")
                .withUndisclosedClaim("is_over_65", "lklxF5jMYlGTPUovMNIvCA")
                .build();

        // Read claims provided by the holder
        JsonNode holderClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-holder-claims.json");
        // Read claims added by the issuer
        JsonNode issuerClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-issuer-claims.json");

        // Merge both
        ((ObjectNode) holderClaimSet).setAll((ObjectNode) issuerClaimSet);

        SdJwt sdJwt = SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(holderClaimSet)
                .withSigner(testSettings.issuerSigContext.signer)
                .withKeyId(testSettings.issuerSigContext.keyId)
                .build();

        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        JsonNode expected = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-issuer-payload.json");
        assertEquals(expected, jwt.getPayload());

        String sdJwtString = sdJwt.toSdJwtString();

        SdJwtVP actualSdJwt = SdJwtVP.of(sdJwtString);

        String expectedString = TestUtils.readFileAsString(getClass(), "sdjwt/s3.3-unsecured-sd-jwt.txt");
        SdJwtVP expecteSdJwt = SdJwtVP.of(expectedString);

        TestCompareSdJwt.compare(expecteSdJwt, actualSdJwt);

    }

    @Test
    public void testIssuerSignedJWTWithUndisclosedClaims6_1() {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.1-issued-payload.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        // System.out.println(sdJwtVP.verbose());
        assertEquals(0, sdJwtVP.getRecursiveDigests().size());
        assertEquals(0, sdJwtVP.getGhostDigests().size());
    }

    @Test
    public void testA1_Example2_with_nested_disclosure_and_decoy_claims() {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/a1.example2-sdjwt.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        // System.out.println(sdJwtVP.verbose());
        assertEquals(10, sdJwtVP.getDisclosures().size());
        assertEquals(0, sdJwtVP.getRecursiveDigests().size());
        assertEquals(0, sdJwtVP.getGhostDigests().size());
    }

    @Test
    public void testS7_3_RecursiveDisclosureOfStructuredSdJwt() {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s7.3-sdjwt.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        // System.out.println(sdJwtVP.verbose());
        assertEquals(5, sdJwtVP.getDisclosures().size());
        assertEquals(4, sdJwtVP.getRecursiveDigests().size());
        assertEquals(0, sdJwtVP.getGhostDigests().size());
    }

    @Test
    public void testS7_3_GhostDisclosures() {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s7.3-sdjwt+ghost.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        // System.out.println(sdJwtVP.verbose());
        assertEquals(8, sdJwtVP.getDisclosures().size());
        assertEquals(4, sdJwtVP.getRecursiveDigests().size());
        assertEquals(3, sdJwtVP.getGhostDigests().size());
    }

    @Test
    public void testS7_3_VerifyIssuerSignaturePositive() throws JOSEException, ParseException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s7.3-sdjwt.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);

        String jws = sdJwtVP.getIssuerSignedJWT().toJws();
        JWSObject parse = JWSObject.parse(jws);
        Base64URL parsedPart = parse.getParsedParts()[1];

        IssuerSignedJWT issuerSignedJWT = new IssuerSignedJWT(parsedPart, testSettings.issuerSigContext.signer, testSettings.issuerSigContext.keyId, testSettings.jwsAlgorithm, "vc+sd-jwt");

        sdJwtVP.getIssuerSignedJWT().verifySignature(testSettings.issuerVerifierContext.verifier);
    }

    @Test(expected = JOSEException.class)
    public void testS7_3_VerifyIssuerSignatureNegative() throws JOSEException {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s7.3-sdjwt.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        sdJwtVP.getIssuerSignedJWT().verifySignature(testSettings.holderVerifierContext.verifier);
    }

    @Test
    public void testS6_2_PresentationPositive() throws JOSEException, ParseException {
        String jwsType = KeyBindingJWT.TYP;
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        JsonNode keyBindingClaims = TestUtils.readClaimSet(getClass(), "sdjwt/s6.2-key-binding-claims.json");
        String presentation = sdJwtVP.present(null, keyBindingClaims,
                testSettings.holderSigContext.signer, testSettings.holderSigContext.keyId, testSettings.jwsAlgorithm, jwsType);

        SdJwtVP presenteSdJwtVP = SdJwtVP.of(presentation);
        assertTrue(presenteSdJwtVP.getKeyBindingJWT().isPresent());

        // Verify with public key from settings
        presenteSdJwtVP.getKeyBindingJWT().get().verifySignature(testSettings.holderVerifierContext.verifier);

        // Verify with public key from cnf claim
        presenteSdJwtVP.getKeyBindingJWT().get()
                .verifySignature(TestSettings.verifierContextFrom(presenteSdJwtVP.getCnfClaim(), "ES256"));
    }

    @Test(expected = JOSEException.class)
    public void testS6_2_PresentationNegative() throws JOSEException, ParseException {
        String jwsType = "vc+sd-jwt";
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        JsonNode keyBindingClaims = TestUtils.readClaimSet(getClass(), "sdjwt/s6.2-key-binding-claims.json");
        String presentation = sdJwtVP.present(null, keyBindingClaims,
                testSettings.holderSigContext.signer, testSettings.holderSigContext.keyId, testSettings.jwsAlgorithm, jwsType);

        SdJwtVP presenteSdJwtVP = SdJwtVP.of(presentation);
        assertTrue(presenteSdJwtVP.getKeyBindingJWT().isPresent());
        // Verify with public key from cnf claim
        presenteSdJwtVP.getKeyBindingJWT().get()
                .verifySignature(TestSettings.verifierContextFrom(presenteSdJwtVP.getCnfClaim(), "ES256"));

        // Verify with wrong public key from settings (issuer)
        presenteSdJwtVP.getKeyBindingJWT().get().verifySignature(testSettings.issuerVerifierContext.verifier);
    }
    
    @Test
    public void testS6_2_PresentationPartialDisclosure() throws ParseException, JOSEException {
        String jwsType = "vc+sd-jwt";
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVPString);
        JsonNode keyBindingClaims = TestUtils.readClaimSet(getClass(), "sdjwt/s6.2-key-binding-claims.json");
        // disclose only the given_name
        String presentation = sdJwtVP.present(List.of("jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"),
                keyBindingClaims, testSettings.holderSigContext.signer, testSettings.holderSigContext.keyId, testSettings.jwsAlgorithm, jwsType);

        SdJwtVP presenteSdJwtVP = SdJwtVP.of(presentation);
        assertTrue(presenteSdJwtVP.getKeyBindingJWT().isPresent());

        // Verify with public key from cnf claim
        presenteSdJwtVP.getKeyBindingJWT().get()
                .verifySignature(TestSettings.verifierContextFrom(presenteSdJwtVP.getCnfClaim(), "ES256"));
    }

    @Test
    public void testOf_validInput() {
        String sdJwtString = TestUtils.readFileAsString(getClass(), "sdjwt/s6.2-presented-sdjwtvp.txt");
        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtString);

        assertNotNull(sdJwtVP);
        assertEquals(4, sdJwtVP.getDisclosures().size());
    }

    @Test
    public void testOf_MalformedSdJwt_ThrowsIllegalArgumentException() {
        // Given
        String malformedSdJwt = "issuer-signed-jwt"; // missing delimiter at the end

        // When & Then
        var exception = assertThrows(IllegalArgumentException.class, () -> SdJwtVP.of(malformedSdJwt));
        assertEquals("SD-JWT is malformed, expected to end with ~", exception.getMessage());
    }

}