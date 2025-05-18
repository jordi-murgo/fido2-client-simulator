package com.example.handlers;

import java.util.*;

import com.example.config.CommandOptions;
import com.example.storage.CredentialStore;
import com.example.utils.EncodingUtils;
import com.example.utils.ResponseFormatter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import lombok.extern.slf4j.Slf4j;

/**
 * Base class for FIDO2 handlers providing common functionality.
 */
@Slf4j
public abstract class BaseHandler {
    protected final CredentialStore credentialStore;
    protected final ObjectMapper jsonMapper;
    protected final CommandOptions options;
    protected final ResponseFormatter formatter;
    
    /**
     * Constructs a BaseHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param options The command line options
     */
    public BaseHandler(CredentialStore credentialStore, ObjectMapper jsonMapper, CommandOptions options) {
        this.credentialStore = credentialStore;
        this.jsonMapper = jsonMapper;
        this.options = options;
        this.formatter = new ResponseFormatter(jsonMapper, options);
        configureObjectMapper();
    }
    
    /**
     * Configures the ObjectMapper with common settings.
     * <p>
     * This method sets up the ObjectMapper to exclude null values from serialization
     * and configures pretty printing if the prettyPrint option is enabled.
     * </p>
     */
    protected void configureObjectMapper() {
        // Always exclude null values from serialization
        this.jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        // Enable pretty printing if requested
        if (options.isPrettyPrint()) {
            this.jsonMapper.enable(SerializationFeature.INDENT_OUTPUT);
        } else {
            this.jsonMapper.disable(SerializationFeature.INDENT_OUTPUT);
        }
    }
    
    /**
     * Removes null values from the JSON response.
     * @param jsonResponse The JSON response string
     * @return The JSON response with null values removed
     * @throws JsonProcessingException if JSON processing fails
     */
    protected String removeNulls(String jsonResponse) throws JsonProcessingException {
        try {
            // En lugar de usar deepCopy(), parseamos el JSON a un nuevo ObjectNode
            JsonNode tree = jsonMapper.readTree(jsonResponse);

            // Eliminamos todos los campos con null
            if(options.isRemoveNulls()) {
                removeNullFields(tree);
            }

            return jsonMapper.writeValueAsString(tree);
        } catch (Exception e) {
            // Si hay algún error, devolvemos el JSON original
            return jsonResponse;
        }
    }

    /**
     * Recursively removes all fields with null values from the given JSON node.
     *
     * @param node The root JSON node to process. It can be an ObjectNode or an ArrayNode.
     */
    public void removeNullFields(JsonNode node) {
        if (node instanceof ObjectNode) {
            ObjectNode objectNode = (ObjectNode) node;
            List<String> fieldsToRemove = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();

            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                JsonNode child = entry.getValue();
                if (child.isNull()) {
                    fieldsToRemove.add(entry.getKey());
                } else {
                    removeNullFields(child);
                }
            }

            for (String field : fieldsToRemove) {
                objectNode.remove(field);
            }

        } else if (node.isArray()) {
            for (JsonNode item : node) {
                removeNullFields(item);
            }
        }
    }

    /**
     * Ensures extensions are present in the JSON node.
     * @param node The JSON node to check
     */
    protected void ensureExtensions(JsonNode node) {
        if (node instanceof ObjectNode && !node.has("extensions")) {
            ((ObjectNode) node).putObject("extensions");
        }
    }

    /**
     * Ensures extensions are present in the options.
     * This modifies the request in-place to add an empty extensions object if missing.
     * @param json The JSON string to check
     * @return The JSON with extensions added if needed
     */
    protected String ensureExtensionsInJson(String json) {
        try {
            ObjectNode node = (ObjectNode) jsonMapper.readTree(json);
            if (!node.has("extensions")) {
                node.putObject("extensions");
            }
            return jsonMapper.writeValueAsString(node);
        } catch (Exception e) {
            // If we can't process JSON, return original
            return json;
        }
    }

    /**
     * Ensures extensions are present in the options.
     * @param options The options to check
     * @return A version of options with extensions added if needed
     */
    protected PublicKeyCredentialRequestOptions ensureExtensions(PublicKeyCredentialRequestOptions options) {
        if (options.getExtensions() == null) {
            return options.toBuilder()
                .extensions(AssertionExtensionInputs.builder().build())
                .build();
        }
        return options;
    }

    /**
     * Attempts to decode a potentially Base64-encoded JSON string. This method will try:
     * 1. URL-safe Base64 decoding
     * 2. Standard Base64 decoding
     * 3. Return the original string if both decode attempts fail
     *
     * This is useful for handling WebAuthn data that might be Base64-encoded when passing
     * between systems or through environments that might interfere with JSON formatting.
     *
     * @param potentiallyEncodedJson A string that may be Base64 encoded JSON
     * @return The decoded JSON string or the original string if not Base64 encoded
     */
    public static String tryDecodeBase64Json(String potentiallyEncodedJson) {
        try {
            // Try to decode the options JSON as a Base64 URL string
            return new String(EncodingUtils.base64UrlDecode(potentiallyEncodedJson));
        } catch (Exception e) {
            try {
                // Try to decode the options JSON as a standard Base64 string
                return new String(EncodingUtils.base64Decode(potentiallyEncodedJson));
            } catch (Exception e2) {
                // If it's not a Base64 string, just return it as is
                return potentiallyEncodedJson;
            }
        }
    }

} 
