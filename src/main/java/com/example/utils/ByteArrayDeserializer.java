package com.example.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.yubico.webauthn.data.ByteArray;

/**
 * Custom deserializer for ByteArray that handles multiple formats:
 * 1. Base64 encoded string (with +, /, = characters)
 * 2. Base64url encoded string (with -, _, no padding)
 * 3. Array of integer bytes (PingOne format with signed bytes -128 to 127)
 * 4. Array of unsigned bytes (0-255)
 * <p>
 * For string inputs, this deserializer automatically detects the format by looking
 * for Base64-specific characters (+, /, =) and tries Base64 first if found,
 * otherwise falls back to Base64URL.
 * </p>
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
        
        // Case 1: If it's a text node, detect and decode Base64 or Base64URL
        if (node instanceof TextNode) {
            String encodedString = ((TextNode) node).asText();
            log.trace("Deserializing ByteArray field '{}' from encoded string ({} chars): {}", 
                currentName, encodedString.length(), encodedString);
                
            try {
                byte[] bytes = decodeWithFormatDetection(encodedString, currentName);
                log.trace("Decoded ByteArray field '{}' to {} bytes: {}", 
                    currentName, bytes.length, Arrays.toString(bytes));
                return new ByteArray(bytes);
            } catch (Exception e) {
                log.error("Error decoding string for field '{}': {}", currentName, e.getMessage(), e);
                throw new IOException("Unable to decode ByteArray from string: " + e.getMessage(), e);
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
                             ". Expected either a base64/base64url encoded string or an array of integers.");
    }
    
    /**
     * Attempts to decode a string by detecting its format based on characteristic characters.
     * If the string contains Base64-specific characters (+, /, =), it tries Base64 first.
     * Otherwise, or if Base64 fails, it tries Base64URL.
     * 
     * @param encodedString The string to decode
     * @param fieldName The field name for logging
     * @return The decoded bytes
     * @throws IllegalArgumentException if decoding fails with both formats
     */
    private byte[] decodeWithFormatDetection(String encodedString, String fieldName) {
        // Check for Base64-specific characters
        boolean hasBase64Chars = encodedString.contains("+") || encodedString.contains("/");
        boolean hasBase64Padding = encodedString.endsWith("=");
        
        if (hasBase64Chars || hasBase64Padding) {
            // Try Base64 first
            log.debug("Field '{}' appears to be Base64 encoded (found {}{}), trying Base64 decoder", 
                     fieldName, 
                     hasBase64Chars ? "+/ chars" : "",
                     hasBase64Padding ? " padding" : "");
            
            try {
                byte[] decoded = Base64.getDecoder().decode(encodedString);
                log.debug("Successfully decoded field '{}' as Base64: {} bytes", fieldName, decoded.length);
                return decoded;
            } catch (Exception e) {
                log.debug("Base64 decoding failed for field '{}', trying Base64URL: {}", fieldName, e.getMessage());
            }
        }
        
        // Try Base64URL (either as primary attempt or as fallback)
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encodedString);
            log.debug("Successfully decoded field '{}' as Base64URL: {} bytes", fieldName, decoded.length);
            return decoded;
        } catch (Exception e) {
            // If both decoders fail, throw an exception
            throw new IllegalArgumentException(
                String.format("Failed to decode field '%s' with both Base64 and Base64URL decoders. " +
                             "String: %s, Error: %s", 
                             fieldName, encodedString, e.getMessage()));
        }
    }
}
