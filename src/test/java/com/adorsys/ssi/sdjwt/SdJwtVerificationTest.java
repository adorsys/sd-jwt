
package com.adorsys.ssi.sdjwt;

import com.adorsys.ssi.sdjwt.exception.SdJwtVerificationException;
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
public class SdJwtVerificationTest {
    static ObjectMapper mapper = new ObjectMapper();
    static TestSettings testSettings = TestSettings.getInstance();

    @Test
    public void settingsTest() {
        JWSSigner issuerSignerContext = testSettings.issuerSigContext.signer;
        assertNotNull(issuerSignerContext);
    }

    @Test
    public void testSdJwtVerification_FlatSdJwt() throws SdJwtVerificationException {
        for (String hashAlg : List.of("sha-256", "sha-384", "sha-512")) {
            var sdJwt = exampleFlatSdJwtV1()
                    .withHashAlgorithm(hashAlg)
                    .build();

            sdJwt.verify(defaultVerificationOptions().build());
        }
    }

    @Test
    public void testSdJwtVerification_SdJwtWithUndisclosedNestedFields() throws SdJwtVerificationException {
        var sdJwt = exampleSdJwtWithUndisclosedNestedFieldsV1().build();
        sdJwt.verify(defaultVerificationOptions().build());
    }

    @Test
    public void testSdJwtVerification_SdJwtWithUndisclosedArrayElements() throws Exception {
        var sdJwt = exampleSdJwtWithUndisclosedArrayElementsV1().build();
        sdJwt.verify(defaultVerificationOptions().build());
    }

    @Test
    public void testSdJwtVerification_RecursiveSdJwt() throws Exception {
        var sdJwt = exampleRecursiveSdJwtV1().build();
        sdJwt.verify(defaultVerificationOptions().build());
    }

    @Test
    public void sdJwtVerificationShouldFail_OnInsecureHashAlg() {
        var sdJwt = exampleFlatSdJwtV1()
                .withHashAlgorithm("sha-224") // not deemed secure
                .build();

        var exception = assertThrows(
                SdJwtVerificationException.class,
                () -> sdJwt.verify(defaultVerificationOptions().build())
        );

        assertEquals("Unexpected or insecure hash algorithm: sha-224", exception.getMessage());
    }

    @Test
    public void sdJwtVerificationShouldFail_WithWrongVerifier() {
        var sdJwt = exampleFlatSdJwtV1().build();
        var exception = assertThrows(
                SdJwtVerificationException.class,
                () -> sdJwt.verify(defaultVerificationOptions()
                        .withVerifier(testSettings.holderVerifierContext.verifier) // wrong verifier
                        .build())
        );

        assertEquals("Invalid Issuer-Signed JWT", exception.getMessage());
        assertEquals("Invalid JWS signature", exception.getCause().getMessage());
    }

    @Test
    public void sdJwtVerificationShouldFail_IfExpired() {
        long now = Instant.now().getEpochSecond();

        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("given_name", "John");
        claimSet.put("exp", now - 1000); // expired 1000 seconds ago

        // Exp claim is plain
        var sdJwtV1 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder().build()).build();
        // Exp claim is undisclosed
        var sdJwtV2 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder()
                .withRedListedClaimNames(DisclosureRedList.of(Set.of()))
                .withUndisclosedClaim("exp", "eluV5Og3gSNII8EYnsxA_A")
                .build()).build();

        for (SdJwt sdJwt : List.of(sdJwtV1, sdJwtV2)) {
            var exception = assertThrows(
                    SdJwtVerificationException.class,
                    () -> sdJwt.verify(defaultVerificationOptions()
                            .withValidateExpirationClaim(true)
                            .build())
            );

            assertEquals("JWT has expired", exception.getMessage());
        }
    }

    @Test
    public void sdJwtVerificationShouldFail__IfExpired_CaseExpInvalid() {
        // exp: null
        ObjectNode claimSet1 = mapper.createObjectNode();
        claimSet1.put("given_name", "John");

        // exp: invalid
        ObjectNode claimSet2 = mapper.createObjectNode();
        claimSet1.put("given_name", "John");
        claimSet1.put("exp", "should-not-be-a-string");

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .build();

        var sdJwtV1 = exampleFlatSdJwtV2(claimSet1, disclosureSpec).build();
        var sdJwtV2 = exampleFlatSdJwtV2(claimSet2, disclosureSpec).build();

        for (SdJwt sdJwt : List.of(sdJwtV1, sdJwtV2)) {
            var exception = assertThrows(
                    SdJwtVerificationException.class,
                    () -> sdJwt.verify(defaultVerificationOptions()
                            .withValidateExpirationClaim(true)
                            .build())
            );

            assertEquals("Missing or invalid 'exp' claim", exception.getMessage());
        }
    }

    @Test
    public void sdJwtVerificationShouldFail__IfIssuedInTheFuture() {
        long now = Instant.now().getEpochSecond();

        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("given_name", "John");
        claimSet.put("iat", now + 1000); // issued in the future

        // Exp claim is plain
        var sdJwtV1 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder().build()).build();
        // Exp claim is undisclosed
        var sdJwtV2 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder()
                .withRedListedClaimNames(DisclosureRedList.of(Set.of()))
                .withUndisclosedClaim("iat", "eluV5Og3gSNII8EYnsxA_A")
                .build()).build();

        for (SdJwt sdJwt : List.of(sdJwtV1, sdJwtV2)) {
            var exception = assertThrows(
                    SdJwtVerificationException.class,
                    () -> sdJwt.verify(defaultVerificationOptions()
                            .withValidateIssuedAtClaim(true)
                            .build())
            );

            assertEquals("JWT issued in the future", exception.getMessage());
        }
    }

    @Test
    public void sdJwtVerificationShouldFail__IfNbfInvalid() {
        long now = Instant.now().getEpochSecond();

        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("given_name", "John");
        claimSet.put("nbf", now + 1000); // now will be too soon to accept the jwt

        // Exp claim is plain
        var sdJwtV1 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder().build()).build();
        // Exp claim is undisclosed
        var sdJwtV2 = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder()
                .withRedListedClaimNames(DisclosureRedList.of(Set.of()))
                .withUndisclosedClaim("iat", "eluV5Og3gSNII8EYnsxA_A")
                .build()).build();

        for (SdJwt sdJwt : List.of(sdJwtV1, sdJwtV2)) {
            var exception = assertThrows(
                    SdJwtVerificationException.class,
                    () -> sdJwt.verify(defaultVerificationOptions()
                            .withValidateNotBeforeClaim(true)
                            .build())
            );

            assertEquals("JWT is not yet valid", exception.getMessage());
        }
    }

    @Test
    public void sdJwtVerificationShouldFail_IfSdArrayElementIsNotString() throws JsonProcessingException {
        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("given_name", "John");
        claimSet.set("_sd", mapper.readTree("[123]"));

        var sdJwt = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder().build()).build();

        var exception = assertThrows(
                SdJwtVerificationException.class,
                () -> sdJwt.verify(defaultVerificationOptions()
                        .build())
        );

        assertEquals("Unexpected non-string element inside _sd array: 123", exception.getMessage());
    }

    @Test
    public void sdJwtVerificationShouldFail_IfForbiddenClaimNames() {
        for (String forbiddenClaimName : List.of("_sd", "...")) {
            ObjectNode claimSet = mapper.createObjectNode();
            claimSet.put(forbiddenClaimName, "Value");

            var sdJwt = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder()
                    .withUndisclosedClaim(forbiddenClaimName, "eluV5Og3gSNII8EYnsxA_A")
                    .build()).build();

            var exception = assertThrows(
                    SdJwtVerificationException.class,
                    () -> sdJwt.verify(defaultVerificationOptions().build())
            );

            assertEquals("Disclosure claim name must not be '_sd' or '...'", exception.getMessage());
        }
    }

    @Test
    public void sdJwtVerificationShouldFail_IfDuplicateDigestValue() {
        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("given_name", "John"); // this same field will also be nested

        var sdJwt = exampleFlatSdJwtV2(claimSet, DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build()).build();

        var exception = assertThrows(
                SdJwtVerificationException.class,
                () -> sdJwt.verify(defaultVerificationOptions().build())
        );

        assertTrue(exception.getMessage().startsWith("A digest was encounted more than once:"));
    }

    private SdJwtVerificationOptions.Builder defaultVerificationOptions() {
        return SdJwtVerificationOptions.builder()
                .withVerifier(testSettings.issuerVerifierContext.verifier)
                .withValidateIssuedAtClaim(false)
                .withValidateExpirationClaim(false)
                .withValidateNotBeforeClaim(false);
    }

    private SdJwt.Builder exampleFlatSdJwtV1() {
        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("sub", "6c5c0a49-b589-431d-bae7-219122a9ec2c");
        claimSet.put("given_name", "John");
        claimSet.put("family_name", "Doe");
        claimSet.put("email", "john.doe@example.com");

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("family_name", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("email", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build();

        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withSigner(testSettings.issuerSigContext.signer);
    }

    private SdJwt.Builder exampleFlatSdJwtV2(ObjectNode claimSet, DisclosureSpec disclosureSpec) {
        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withSigner(testSettings.issuerSigContext.signer);
    }

    private SdJwt.Builder exampleSdJwtWithUndisclosedNestedFieldsV1() {
        ObjectNode addressClaimSet = mapper.createObjectNode();
        addressClaimSet.put("street_address", "Rue des Oliviers");
        addressClaimSet.put("city", "Paris");
        addressClaimSet.put("country", "France");

        DisclosureSpec addrDisclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("street_address", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("city", "G02NSrQfjFXQ7Io09syajA")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build();

        SdJwt addrSdJWT = SdJwt.builder()
                .withDisclosureSpec(addrDisclosureSpec)
                .withClaimSet(addressClaimSet)
                .build();

        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("sub", "6c5c0a49-b589-431d-bae7-219122a9ec2c");
        claimSet.put("given_name", "John");
        claimSet.put("family_name", "Doe");
        claimSet.put("email", "john.doe@example.com");
        claimSet.set("address", addrSdJWT.asNestedPayload());

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("family_name", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("email", "eI8ZWm9QnKPpNPeNenHdhQ")
                .build();

        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withNestedSdJwt(addrSdJWT)
                .withSigner(testSettings.issuerSigContext.signer);
    }

    private SdJwt.Builder exampleSdJwtWithUndisclosedNestedFieldsV2(
            ObjectNode claimSet, DisclosureSpec disclosureSpec) {
        ObjectNode addressClaimSet = mapper.createObjectNode();
        addressClaimSet.put("street_address", "Rue des Oliviers");
        addressClaimSet.put("city", "Paris");
        addressClaimSet.put("country", "France");

        DisclosureSpec addrDisclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("street_address", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("city", "G02NSrQfjFXQ7Io09syajA")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build();

        SdJwt addrSdJWT = SdJwt.builder()
                .withDisclosureSpec(addrDisclosureSpec)
                .withClaimSet(addressClaimSet)
                .build();

        claimSet.set("address", addrSdJWT.asNestedPayload());

        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withNestedSdJwt(addrSdJWT)
                .withSigner(testSettings.issuerSigContext.signer);
    }

    private SdJwt.Builder exampleSdJwtWithUndisclosedArrayElementsV1() throws JsonProcessingException {
        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("sub", "6c5c0a49-b589-431d-bae7-219122a9ec2c");
        claimSet.put("given_name", "John");
        claimSet.put("family_name", "Doe");
        claimSet.put("email", "john.doe@example.com");
        claimSet.set("nationalities", mapper.readTree("[\"US\", \"DE\"]"));

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("family_name", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("email", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withUndisclosedArrayElt("nationalities", 1, "nPuoQnkRFq3BIeAm7AnXFA")
                .withDecoyArrayElt("nationalities", 2, "G02NSrQfjFXQ7Io09syajA")
                .build();

        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withSigner(testSettings.issuerSigContext.signer);
    }

    private SdJwt.Builder exampleRecursiveSdJwtV1() {
        ObjectNode addressClaimSet = mapper.createObjectNode();
        addressClaimSet.put("street_address", "Rue des Oliviers");
        addressClaimSet.put("city", "Paris");
        addressClaimSet.put("country", "France");

        DisclosureSpec addrDisclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("street_address", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("city", "G02NSrQfjFXQ7Io09syajA")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build();

        SdJwt addrSdJWT = SdJwt.builder()
                .withDisclosureSpec(addrDisclosureSpec)
                .withClaimSet(addressClaimSet)
                .build();

        ObjectNode claimSet = mapper.createObjectNode();
        claimSet.put("sub", "6c5c0a49-b589-431d-bae7-219122a9ec2c");
        claimSet.put("given_name", "John");
        claimSet.put("family_name", "Doe");
        claimSet.put("email", "john.doe@example.com");
        claimSet.set("address", addrSdJWT.asNestedPayload());

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("family_name", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("email", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withUndisclosedClaim("address", "BZFzhQsdPfZY1WSL-1GXKg")
                .build();

        return SdJwt.builder()
                .withDisclosureSpec(disclosureSpec)
                .withClaimSet(claimSet)
                .withNestedSdJwt(addrSdJWT)
                .withSigner(testSettings.issuerSigContext.signer);
    }
}
