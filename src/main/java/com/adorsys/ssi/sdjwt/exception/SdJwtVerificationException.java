package com.adorsys.ssi.sdjwt.exception;

import java.security.GeneralSecurityException;

/**
 * Exception indicating that the SD JWT verification failed
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVerificationException extends GeneralSecurityException {

    public SdJwtVerificationException() {
        super();
    }

    public SdJwtVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SdJwtVerificationException(String msg) {
        super(msg);
    }

    public SdJwtVerificationException(Throwable cause) {
        super(cause);
    }
}