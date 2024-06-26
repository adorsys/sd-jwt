
package de.adorsys.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class ArrayElementDisclosureTest {

        @Test
        public void testSdJwtWithUndiclosedArrayElements6_1() {
                JsonNode claimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s6.1-holder-claims.json");

                DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                                .withUndisclosedClaim("email", "JnwGqRFZjMprsoZobherdQ")
                                .withUndisclosedClaim("phone_number", "ffZ03jm_zeHyG4-yoNt6vg")
                                .withUndisclosedClaim("address", "INhOGJnu82BAtsOwiCJc_A")
                                .withUndisclosedClaim("birthdate", "d0l3jsh5sBzj2oEhZxrJGw")
                                .withUndisclosedArrayElt("nationalities", 1, "nPuoQnkRFq3BIeAm7AnXFA")
                                .build();

                SdJwt sdJwt = SdJwt.builder()
                                .withDisclosureSpec(disclosureSpec)
                                .withClaimSet(claimSet)
                                .build();

                IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

                JsonNode expected = TestUtils.readClaimSet(getClass(),
                                "sdjwt/s6.1-issuer-payload-udisclosed-array-ellement.json");
                assertEquals(expected, jwt.getPayload());
        }

        @Test
        public void testSdJwtWithUndiclosedAndDecoyArrayElements6_1() {
                JsonNode claimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s6.1-holder-claims.json");

                DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                                .withUndisclosedClaim("email", "JnwGqRFZjMprsoZobherdQ")
                                .withUndisclosedClaim("phone_number", "ffZ03jm_zeHyG4-yoNt6vg")
                                .withUndisclosedClaim("address", "INhOGJnu82BAtsOwiCJc_A")
                                .withUndisclosedClaim("birthdate", "d0l3jsh5sBzj2oEhZxrJGw")
                                .withUndisclosedArrayElt("nationalities", 0, "Qg_O64zqAxe412a108iroA")
                                .withUndisclosedArrayElt("nationalities", 1, "nPuoQnkRFq3BIeAm7AnXFA")
                                .withDecoyArrayElt("nationalities", 1, "5bPs1IquZNa0hkaFzzzZNw")
                                .build();

                SdJwt sdJwt = SdJwt.builder()
                                .withDisclosureSpec(disclosureSpec)
                                .withClaimSet(claimSet)
                                .build();
                IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

                JsonNode expected = TestUtils.readClaimSet(getClass(),
                                "sdjwt/s6.1-issuer-payload-decoy-array-ellement.json");
                assertEquals(expected, jwt.getPayload());
        }
}
