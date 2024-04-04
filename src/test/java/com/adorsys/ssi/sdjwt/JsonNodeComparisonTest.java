
package com.adorsys.ssi.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class JsonNodeComparisonTest {
    @Test
    public void testJsonNodeEquality() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        JsonNode node1 = mapper.readTree("{\"name\":\"John\", \"age\":30}");
        JsonNode node2 = mapper.readTree("{\"age\":30, \"name\":\"John\"}");

        assertEquals("JsonNode objects should be equal", node1, node2);
    }
}
