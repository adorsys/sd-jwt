package de.adorsys.sdjwt.sdjwtvp;

import de.adorsys.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.junit.Test;

public class KeyBindingJwtVerificationOptsTest {

    @Test(expected = IllegalArgumentException.class)
    public void buildShouldFail_IfKeyBindingRequired_AndNonceNotSpecified() {
        KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void buildShouldFail_IfKeyBindingRequired_AndNonceEmpty() {
        KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withNonce("")
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void buildShouldFail_IfKeyBindingRequired_AndAudNotSpecified() {
        KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withNonce("12345678")
                .build();
    }

}