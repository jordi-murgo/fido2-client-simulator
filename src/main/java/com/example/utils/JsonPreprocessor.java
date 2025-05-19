package com.example.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Utility class for preprocessing WebAuthn JSON to ensure compatibility with the Yubico WebAuthn library.
 * This handles filtering of unsupported COSE algorithms.
 */
@Slf4j
public class JsonPreprocessor {
    
    private static final ObjectMapper mapper = new ObjectMapper();
    
    // Lista de algoritmos soportados
    private static final List<Integer> SUPPORTED_ALGORITHMS = List.of(
        -7,   // ES256
        -257  // RS256
    );

    /**
     * Preprocesses WebAuthn creation options JSON to ensure compatibility.
     * Removes any unsupported COSE algorithm identifiers from pubKeyCredParams.
     * 
     * @param json The original JSON string
     * @return The processed JSON string with only supported algorithms
     */
    public static String preprocessWebAuthnJson(String json) {
        try {
            JsonNode rootNode = mapper.readTree(json);
            
            if (rootNode.has("pubKeyCredParams") && rootNode.get("pubKeyCredParams").isArray()) {
                ArrayNode pubKeyCredParams = (ArrayNode) rootNode.get("pubKeyCredParams");
                ArrayNode filteredParams = filterAlgorithms(pubKeyCredParams);
                
                // Reemplazar el array original con el filtrado
                ((ObjectNode) rootNode).set("pubKeyCredParams", filteredParams);
                
                // Si no quedaron algoritmos, añadir uno por defecto
                if (filteredParams.size() == 0) {
                    log.error("No supported algorithms found in pubKeyCredParams");
                    throw new IllegalArgumentException("No supported algorithms found in pubKeyCredParams");
                }
                
                return mapper.writeValueAsString(rootNode);
            }
            return json;
        } catch (Exception e) {
            log.error("Error preprocessing WebAuthn JSON: {}", e.getMessage());
            return json; // En caso de error, devolver el JSON original
        }
    }
    
    /**
     * Filtra los algoritmos no soportados del array pubKeyCredParams.
     */
    private static ArrayNode filterAlgorithms(ArrayNode pubKeyCredParams) {
        ArrayNode result = mapper.createArrayNode();
        
        pubKeyCredParams.forEach(param -> {
            if (param.has("alg")) {
                int algValue = param.get("alg").asInt();
                if (SUPPORTED_ALGORITHMS.contains(algValue)) {
                    result.add(param);
                    log.debug("Including supported COSE algorithm: {}", algValue);
                } else {
                    log.info("Filtering out unsupported COSE algorithm: {}", algValue);
                }
            } else {
                // Mantener entradas sin especificación de algoritmo (por si acaso)
                result.add(param);
            }
        });
        
        return result;
    }
}