
package com.adorsys.ssi.sdjwt;

import org.junit.Test;
import org.keycloak.sdjwt.DisclosureSpec;

public class DisclosureRedListTest {

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedInObjectClaim() {
        org.keycloak.sdjwt.DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "2GLC42sKQveCfGfryNRN9w")
                .withUndisclosedClaim("vct")
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedInArrayClaim() {
        org.keycloak.sdjwt.DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "2GLC42sKQveCfGfryNRN9w")
                .withUndisclosedArrayElt("iat", 0, "2GLC42sKQveCfGfryNRN9w")
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedInDecoyArrayClaim() {
        org.keycloak.sdjwt.DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "2GLC42sKQveCfGfryNRN9w")
                .withDecoyArrayElt("exp", 0, "2GLC42sKQveCfGfryNRN9w")
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedIss() {
        org.keycloak.sdjwt.DisclosureSpec.builder().withUndisclosedClaim("iss").build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedInObjectNbf() {
        org.keycloak.sdjwt.DisclosureSpec.builder().withUndisclosedClaim("nbf").build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedCnf() {
        org.keycloak.sdjwt.DisclosureSpec.builder().withUndisclosedClaim("cnf").build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDefaultRedListedStatus() {
        DisclosureSpec.builder().withUndisclosedClaim("status").build();
    }
}
