
package de.adorsys.sdjwt;

import com.fasterxml.jackson.databind.node.TextNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class UndisclosedClaimTest {

    @Before
    public void setUp() throws Exception {
        SdJwtUtils.arrayEltSpaced = false;
    }

    @After
    public void tearDown() throws Exception {
        SdJwtUtils.arrayEltSpaced = true;
    }

    @Test
    public void testToBase64urlEncoded() {
        // Create an instance of UndisclosedClaim with the specified fields
        UndisclosedClaim undisclosedClaim = UndisclosedClaim.builder()
                .withClaimName("family_name")
                .withSalt(new SdJwtSalt("_26bc4LT-ac6q2KI6cBW5es"))
                .withClaimValue(new TextNode("Möbius"))
                .build();

        // Expected Base64 URL encoded string
        String expected = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd";

        // Assert that the base64 URL encoded string from the object matches the
        // expected string
        assertEquals(expected, undisclosedClaim.getDisclosureStrings().get(0));
    }
}
