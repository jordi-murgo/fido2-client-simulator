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
     * This method accepts a String as input.
     * 
     * @param parent The parent node to which the formatted data will be added
     * @param fieldName The name of the field being formatted (e.g., "id", "rawId", "authenticatorData")
     * @param data The binary data to format as a String
     * @return The ResponseFormatter instance for method chaining
     */
    public ResponseFormatter formatString(ObjectNode parent, String fieldName, String data) {
        JsonNode objectNode = data != null ? formatBytes(new ByteArray(data.getBytes()), fieldName, "string") : JsonNodeFactory.instance.nullNode();
        if (objectNode.isTextual()) {
            parent.put(fieldName, objectNode.asText());
        } else {
            parent.set(fieldName, objectNode);
        }
        return this;
    }

    public ResponseFormatter formatNumber(ObjectNode parent, String fieldName, Long data) {
        if (data == null) {
            return this;
        }

        String format = this.formatConfig.get(fieldName);
        if (format == null || format.trim().isEmpty()) {
            format = "number";
        } 

        format = format.trim().toLowerCase();
        log.debug("Formatting number field '{}' as '{}'", fieldName, format);
        
        switch (format) {
            case "remove":
                parent.remove(fieldName);
                break;
            case "number":
                parent.set(fieldName, JsonNodeFactory.instance.numberNode(data));
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
     * Formats a JSON object according to the configured format for the specified field.
     * 
     * @param parent The parent node to which the formatted data will be added
     * @param fieldName The name of the field being formatted
     * @param data The JSON object to format
     * @return The ResponseFormatter instance for method chaining
     */
    public ResponseFormatter formatObject(ObjectNode parent, String fieldName, JsonNode data) {
        if (data == null) {
            return this;
        }

        String format = this.formatConfig.get(fieldName);
        if (format == null || format.trim().isEmpty()) {
            format = "object";
        }

        format = format.trim().toLowerCase();
        log.debug("Formatting object field '{}' as '{}'", fieldName, format);

        switch (format) {
            case "remove":
                parent.remove(fieldName);
                break;
            case "object":
                parent.set(fieldName, data);
                break;
            case "null":
                parent.set(fieldName, JsonNodeFactory.instance.nullNode());
                break;
            case "string":
                parent.put(fieldName, data.toString());
                break;
            case "base64url":
                parent.put(fieldName, java.util.Base64.getUrlEncoder().encodeToString(data.toString().getBytes()));
                break;
            default:
                log.warn("Unknown format '{}', using object", format);
                parent.set(fieldName, data);
                break;
        }

        return this;
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
    public ResponseFormatter formatBytes(ObjectNode parent, String fieldName, byte[] data) {
        if (data == null) {
            return this;
        }
        return formatBytes(parent, fieldName, new ByteArray(data));
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
    public ResponseFormatter formatBytes(ObjectNode parent, String fieldName, ByteArray data) {
        JsonNode objectNode = data != null ? formatBytes(data, fieldName) : JsonNodeFactory.instance.nullNode();
        if (objectNode == null) {
            parent.remove(fieldName);
            return this;
        }
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
    private JsonNode formatBytes(ByteArray data, String fieldName) {
        return formatBytes(data, fieldName, "base64url");
    }
    
    private JsonNode formatBytes(ByteArray data, String fieldName, String defaultFormat) {
        if (data == null) {
            return JsonNodeFactory.instance.nullNode();
        }

        String format = this.formatConfig.get(fieldName);
        
        // Validate format
        if (format == null || format.trim().isEmpty()) {
            log.debug("No format specified for field '{}', using {}", fieldName, defaultFormat);
            format = defaultFormat.toLowerCase();
        } else {
            format = format.trim().toLowerCase();
            log.debug("Formatting field '{}' as '{}'", fieldName, format);
        }
        
        try {
            switch (format) {
                case "remove":
                    return null;
                
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
}
