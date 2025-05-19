package com.example.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.yubico.webauthn.data.ByteArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;

/**
 * Custom deserializer for ByteArray that handles multiple formats:
 * 1. Base64url encoded string (standard WebAuthn format)
 * 2. Array of integer bytes (PingOne format with signed bytes -128 to 127)
 * 3. Array of unsigned bytes (0-255)
 * <p>
 * This flexibility allows the FIDO2 Client Simulator to work with different WebAuthn formats
 * from various providers without requiring manual conversion.
 * </p>
 * 
 * @author Jordi Murgo
 */
public class ByteArrayDeserializer extends JsonDeserializer<ByteArray> {
    private static final Logger log = LoggerFactory.getLogger(ByteArrayDeserializer.class);
    
    @Override
    public ByteArray deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        TreeNode node = p.readValueAsTree();
        String currentName = p.currentName() != null ? p.currentName() : "[unnamed]";
        
        // Case 1: If it's a text node, assume base64url encoding
        if (node instanceof TextNode) {
            String base64url = ((TextNode) node).asText();
            log.trace("Deserializing ByteArray field '{}' from base64url string ({} chars): {}", 
                currentName, base64url.length(), base64url);
                
            try {
                byte[] bytes = EncodingUtils.tryDecodeBase64(base64url.getBytes());
                log.trace("Decoded ByteArray field '{}' to {} bytes: {}", 
                    currentName, bytes.length, Arrays.toString(bytes));
                return new ByteArray(bytes);
            } catch (Exception e) {
                log.error("Error decoding base64url string for field '{}': {}", currentName, e.getMessage(), e);
                throw e;
            }
        } 
        // Case 2: If it's an array node, convert array of integers to bytes
        else if (node instanceof ArrayNode) {
            ArrayNode arrayNode = (ArrayNode) node;
            byte[] bytes = new byte[arrayNode.size()];
            
            log.trace("Deserializing ByteArray field '{}' from array of size: {}", 
                currentName, arrayNode.size());
            
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode elementNode = arrayNode.get(i);
                // Handle both signed (-128 to 127) and unsigned (0-255) byte representations
                int value = elementNode.asInt();
                bytes[i] = (byte) value;
            }
            
            log.trace("Converted ByteArray field '{}' to {} bytes: {}", 
                currentName, bytes.length, Arrays.toString(bytes));
                
            return new ByteArray(bytes);
        }
        
        // If we get here, we couldn't parse the input
        throw new IOException("Unable to deserialize ByteArray from " + node.getClass().getSimpleName() + 
                             ". Expected either a base64url encoded string or an array of integers.");
    }
}
