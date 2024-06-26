
package de.adorsys.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class TestUtils {
    public static JsonNode readClaimSet(Class<?> klass, String path) {
        // try-with-resources closes inputstream!
        try (InputStream is = klass.getClassLoader().getResourceAsStream(path)) {
            return SdJwtUtils.mapper.readTree(is);
        } catch (IOException e) {
            throw new RuntimeException("Error reading file at path: " + path, e);
        }
    }

    public static String readFileAsString(Class<?> klass, String filePath) {
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                (new InputStreamReader(klass.getClassLoader().getResourceAsStream(filePath))))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line); // Appends line without a newline character
            }
        } catch (IOException e) {
            throw new RuntimeException("Error reading file at path: " + filePath, e);
        }
        return stringBuilder.toString();
    }

    public static String splitStringIntoLines(String input, int lineLength) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i += lineLength) {
            int end = Math.min(input.length(), i + lineLength);
            result.append(input, i, end).append("\n");
        }
        return result.toString();
    }

}
