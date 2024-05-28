
package com.adorsys.ssi.sdjwt;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.nimbusds.jose.util.Base64URL;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class SdJwtUtils {

    public static final ObjectMapper mapper = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String encodeNoPad(byte[] bytes) {
        return Base64URL.encode(bytes).toString();
    }

    public static byte[] decodeNoPad(String encoded) {
        return Base64.getUrlDecoder().decode(encoded);
    }

    public static String hashAndBase64EncodeNoPad(byte[] disclosureBytes, String hashAlg) {
        return encodeNoPad(hash(disclosureBytes, hashAlg));
    }

    public static String requireNonEmpty(String str, String message) {
        return Optional.ofNullable(str)
                .filter(s -> !s.isEmpty())
                .orElseThrow(() -> new IllegalArgumentException(message));
    }

    public static String randomSalt() {
        // 16 bytes for 128-bit entropy.
        // Base64url-encoded
        return encodeNoPad(randomBytes(16));
    }

    public static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static String printJsonArray(Object[] array) throws JsonProcessingException {
        if (arrayEltSpaced) {
            return arraySpacedPrettyPrinter.writer.writeValueAsString(array);
        } else {
            return mapper.writeValueAsString(array);
        }
    }

    public static byte[] hash(byte[] bytes, String hashAlg) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return digest.digest(bytes);
    }

    static ArraySpacedPrettyPrinter arraySpacedPrettyPrinter = new ArraySpacedPrettyPrinter();

    static class ArraySpacedPrettyPrinter extends MinimalPrettyPrinter {
        final ObjectMapper prettyPrinObjectMapper;
        final ObjectWriter writer;

        public ArraySpacedPrettyPrinter() {
            prettyPrinObjectMapper = new ObjectMapper();
            prettyPrinObjectMapper.setDefaultPrettyPrinter(this);
            writer = prettyPrinObjectMapper.writer(this);
        }

        @Override
        public void writeArrayValueSeparator(JsonGenerator jg) throws IOException {
            jg.writeRaw(',');
            jg.writeRaw(' ');
        }

        @Override
        public void writeObjectEntrySeparator(JsonGenerator jg) throws IOException {
            jg.writeRaw(',');
            jg.writeRaw(' '); // Add a space after comma
        }

        @Override
        public void writeObjectFieldValueSeparator(JsonGenerator jg) throws IOException {
            jg.writeRaw(':');
            jg.writeRaw(' '); // Add a space after comma
        }
    }

    public static boolean arrayEltSpaced = true;
}
