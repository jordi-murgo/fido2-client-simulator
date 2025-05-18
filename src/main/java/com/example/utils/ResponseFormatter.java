package com.example.utils;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.example.config.CommandOptions;
import com.example.config.ConfigurationManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.ByteArray;

import lombok.extern.slf4j.Slf4j;

/**
 * Utility for formatting binary fields in FIDO2/WebAuthn responses to support multiple output styles.
 * Supports: base64url, base64, bytes (Int8 array)
 *
 * Usage example:
 *   ResponseFormatter formatter = new ResponseFormatter("chrome", jsonMapper);
 *   credentialNode.set("id", formatter.formatBinary(credentialId.getBytes(), "id"));
 */
@Slf4j
public class ResponseFormatter {
    private final ObjectMapper jsonMapper;
    private final CommandOptions options;
    private final Map<String, String> formatConfig;
    
    /**
     * Creates a new ResponseFormatter with the specified format configuration.
     * @param jsonMapper The ObjectMapper to use for JSON operations
     * @param options The command line options containing format settings
     * @throws IllegalArgumentException if jsonMapper or options is null
     */
    public ResponseFormatter(ObjectMapper jsonMapper, CommandOptions options) {
        if (jsonMapper == null) {
            throw new IllegalArgumentException("jsonMapper cannot be null");
        }
        if (options == null) {
            throw new IllegalArgumentException("options cannot be null");
        }
        
        this.jsonMapper = jsonMapper;
        this.options = options;
        
        // Get format name from options, default to "default" if not set
        String formatName = options.getFormat();
        if (formatName == null || formatName.trim().isEmpty()) {
            log.info("No format name provided, using 'default' format");
            formatName = "default";
        }
        
        // Get format configuration from ConfigurationManager
        Map<String, String> config = ConfigurationManager.getInstance().getFormatConfig(formatName);
        
        // Fall back to default format if requested format is not found
        if (config == null) {
            log.warn("Format configuration '{}' not found, using 'default' format", formatName);
            config = ConfigurationManager.getInstance().getFormatConfig("default");
        }
        
        this.formatConfig = config;
        log.debug("Initialized ResponseFormatter with format: {}", formatName);
    }
    
    /**
     * Returns the name of the format being used.
     * @return The format name
     */
    public String getFormatName() {
        return options.getFormat();
    }

    /**
     * Formats binary data according to the configured format for the specified field.
     * This method accepts a byte array as input.
     * 
     * @param parent The parent node to which the formatted data will be added
     * @param fieldName The name of the field being formatted (e.g., "id", "rawId", "authenticatorData")
     * @param data The binary data to format as a byte array
     * @return The ResponseFormatter instance for method chaining
     */
    public ResponseFormatter formatBinary(ObjectNode parent, String fieldName, byte[] data) {
        if (data == null) {
            return this;
        }
        return formatBinary(parent, fieldName, new ByteArray(data));
    }
    
    /**
     * Formats binary data according to the configured format for the specified field.
     * This method accepts a String as input.
     * 
     * @param parent The parent node to which the formatted data will be added
     * @param fieldName The name of the field being formatted (e.g., "id", "rawId", "authenticatorData")
     * @param data The binary data to format as a String
     * @return The ResponseFormatter instance for method chaining
     */
    public ResponseFormatter formatBinary(ObjectNode parent, String fieldName, String data) {
        if (data == null) {
            return this;
        }
        return formatBinary(parent, fieldName, data.getBytes(StandardCharsets.UTF_8));
    }

    public ResponseFormatter formatBinary(ObjectNode parent, String fieldName, long data) {
        String format = this.formatConfig.get(fieldName);
        if (format == null || format.trim().isEmpty()) {
            format = "number";
        } 

        format = format.trim().toLowerCase();
        log.debug("Formatting field '{}' as '{}'", fieldName, format);
        
        switch (format) {
            case "number":
                parent.put(fieldName, data);
                break;
            case "null":
                parent.set(fieldName, JsonNodeFactory.instance.nullNode());
                break;
            case "string":
                parent.put(fieldName, String.valueOf(data));
                break;
            case "base64url":
                parent.put(fieldName, java.util.Base64.getUrlEncoder().encodeToString(String.valueOf(data).getBytes()));
                break;
            default:
                log.warn("Unknown format '{}', using number", format);
                parent.put(fieldName, data);
                break;
        }

        return this;
    }


    /**
     * Formats binary data according to the configured format for the specified field.
     * This method accepts a ByteArray as input and handles the actual formatting.
     * 
     * @param parent The parent node to which the formatted data will be added
     * @param fieldName The name of the field being formatted (e.g., "id", "rawId", "authenticatorData")
     * @param data The binary data to format as a ByteArray
     * @return The ResponseFormatter instance for method chaining
     */
    public ResponseFormatter formatBinary(ObjectNode parent, String fieldName, ByteArray data) {
        JsonNode objectNode = data != null ? formatBinary(data, fieldName) : JsonNodeFactory.instance.nullNode();
        if (objectNode.isTextual()) {
            parent.put(fieldName, objectNode.asText());
        } else {
            parent.set(fieldName, objectNode);
        }
        return this;
    }

    /**
     * Formats binary data according to the configured format for the specified field.
     * This method accepts a ByteArray as input and handles the actual formatting.
     * 
     * @param data The binary data to format as a ByteArray
     * @param fieldName The name of the field being formatted (e.g., "id", "rawId", "authenticatorData")
     * @return A JsonNode containing the formatted data
     */
    private JsonNode formatBinary(ByteArray data, String fieldName) {
        if (data == null) {
            return JsonNodeFactory.instance.nullNode();
        }

        String format = this.formatConfig.get(fieldName);
        
        // Validate format
        if (format == null || format.trim().isEmpty()) {
            log.debug("No format specified for field '{}', using base64url", fieldName);
            format = "base64url";
        } else {
            format = format.trim().toLowerCase();
            log.debug("Formatting field '{}' as '{}'", fieldName, format);
        }
        
        try {
            switch (format.toLowerCase()) {
                case "base64":
                    return JsonNodeFactory.instance.textNode(data.getBase64());
                    
                case "base64url":
                    return JsonNodeFactory.instance.textNode(data.getBase64Url());
                    
                case "bytearray":
                    return bytesToNode(data.getBytes());
                    
                case "intarray":
                    return intArrayToNode(data.getBytes());

                case "hex":
                    return JsonNodeFactory.instance.textNode(data.getHex());
                    
                case "string":
                    try {
                        // Try to decode as UTF-8 string if it's text
                        String str = new String(data.getBytes(), StandardCharsets.UTF_8);
                        return JsonNodeFactory.instance.textNode(str);
                    } catch (Exception e) {
                        log.warn("Error decoding data as UTF-8 string, setting to base64url for field '{}': {}", fieldName, e.getMessage());
                        // Not a valid UTF-8 string, fall through to default
                        return JsonNodeFactory.instance.textNode(data.getBase64Url());
                    }

                case "null":
                    return JsonNodeFactory.instance.nullNode();

                default:
                    log.warn("Unknown format '{}', using base64url for field '{}'", format, fieldName);
                    return JsonNodeFactory.instance.textNode(data.getBase64Url());
            }
        } catch (Exception e) {
            log.error("Error formatting data with format '{}': {}", format, e.getMessage(), e);
            return JsonNodeFactory.instance.textNode(data.getBase64Url());
        }
    }

    /**
     * Converts a byte array to a JSON array of integers (0-255).
     * @param bytes The byte array to convert
     * @return A JsonNode containing the array of integers
     */
    private JsonNode intArrayToNode(byte[] bytes) {
        if (bytes == null) {
            return JsonNodeFactory.instance.nullNode();
        }
        
        ArrayNode array = JsonNodeFactory.instance.arrayNode();
        for (byte b : bytes) {
            array.add(b & 0xFF);
        }
        return array;
    }
    
    /**
     * Converts a byte array to a JSON array of signed bytes (-128 to 127).
     * @param bytes The byte array to convert
     * @return A JsonNode containing the array of signed bytes
     */
    private JsonNode bytesToNode(byte[] bytes) {
        if (bytes == null) {
            return JsonNodeFactory.instance.nullNode();
        }
        
        ArrayNode array = JsonNodeFactory.instance.arrayNode();
        for (byte b : bytes) {
            array.add(b);
        }
        return array;
    }
    
    /**
     * Formats a JSON response string according to the configured format.
     * @param jsonString The JSON string to format
     * @return The formatted JSON string
     */
    public String formatResponse(String jsonString) {
        try {
            // Parse the JSON string to a JsonNode
            JsonNode jsonNode = jsonMapper.readTree(jsonString);
            
            // Format the JSON with pretty printing if enabled
            if (options.isPrettyPrint()) {
                log.debug("Pretty printing JSON response: {}", jsonNode.toString());
                return jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonNode);
            } else {
                log.debug("JSON response: {}", jsonNode.toString());
                return jsonNode.toString();
            }
        } catch (Exception e) {
            log.error("Error formatting JSON response: {}", e.getMessage(), e);
            return jsonString; // Return original string if formatting fails
        }
    }
 

}
