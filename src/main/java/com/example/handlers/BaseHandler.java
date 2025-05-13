package com.example.handlers;

import java.util.Base64;

import com.example.storage.CredentialStore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

/**
 * Base class for FIDO2 handlers providing common functionality.
 */
public abstract class BaseHandler {
    protected final CredentialStore credentialStore;
    protected final ObjectMapper jsonMapper;
    
    /**
     * Constructs a BaseHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     */
    public BaseHandler(CredentialStore credentialStore, ObjectMapper jsonMapper) {
        this.credentialStore = credentialStore;
        this.jsonMapper = jsonMapper;
        configureObjectMapper();
    }
    
    /**
     * Configures the ObjectMapper to exclude null values.
     */
    protected void configureObjectMapper() {
        this.jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }
    
    /**
     * Adds rawId to the JSON response.
     * @param jsonResponse The JSON response string
     * @return The JSON response with rawId added
     * @throws JsonProcessingException if JSON processing fails
     */
    protected String addRawIdToResponse(String jsonResponse) throws JsonProcessingException {
        try {
            // En lugar de usar deepCopy(), parseamos el JSON a un nuevo ObjectNode
            JsonNode tree = jsonMapper.readTree(jsonResponse);
            ObjectNode responseNode = jsonMapper.createObjectNode();
            
            // Copiamos manualmente todos los campos
            tree.fieldNames().forEachRemaining(fieldName -> {
                responseNode.set(fieldName, tree.get(fieldName));
            });
            
            // Añadimos rawId si es necesario
            if (responseNode.has("id") && !responseNode.has("rawId")) {
                responseNode.put("rawId", responseNode.get("id").asText());
            }
            
            return jsonMapper.writeValueAsString(responseNode);
        } catch (Exception e) {
            // Si hay algún error, devolvemos el JSON original
            return jsonResponse;
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
            return new String(Base64.getUrlDecoder().decode(potentiallyEncodedJson));
        } catch (Exception e) {
            try {
                // Try to decode the options JSON as a standard Base64 string
                return new String(Base64.getDecoder().decode(potentiallyEncodedJson));
            } catch (Exception e2) {
                // If it's not a Base64 string, just return it as is
                return potentiallyEncodedJson;
            }
        }
    }

} 
