package com.example.handlers;

import com.example.storage.CredentialMetadata;
import com.example.storage.CredentialStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.ByteArray;

import java.io.File;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handler for displaying keystore and metadata information.
 * 
 * This handler provides diagnostic capabilities by displaying all credentials
 * stored in the system along with their metadata. It helps with debugging
 * and credential management.
 * 
 * @author Jordi Murgo
 * @since 1.1
 */
public class InfoHandler implements CommandHandler {
    private static final Logger LOGGER = Logger.getLogger(InfoHandler.class.getName());
    
    private final CredentialStore credentialStore;
    private final ObjectMapper jsonMapper;
    private final boolean verboseOutput;
    
    /**
     * Creates a new InfoHandler.
     * 
     * @param credentialStore The credential store containing the credentials
     * @param jsonMapper The JSON mapper for formatting output
     * @param verbose Whether to include verbose details in the output
     */
    public InfoHandler(CredentialStore credentialStore, ObjectMapper jsonMapper, boolean verbose) {
        this.credentialStore = credentialStore;
        this.jsonMapper = jsonMapper;
        this.verboseOutput = verbose;
    }
    
    /**
     * Handles the info operation, displaying all credentials and their metadata.
     * 
     * @param requestJson Usually empty for info operations, can contain filter criteria in the future
     * @return A JSON string containing detailed information about all credentials
     * @throws Exception if an error occurs during processing
     */
    @Override
    public String handleRequest(String requestJson) throws Exception {
        LOGGER.log(Level.INFO, "Processing info request for credential store content");
        
        // Create the root JSON object for our response
        ObjectNode rootNode = jsonMapper.createObjectNode();
        
        // Add summary information
        Map<String, CredentialMetadata> metadataMap = credentialStore.getMetadataMap();
        rootNode.put("totalCredentials", metadataMap.size());
        
        // Get all relying parties
        ArrayNode rpArray = rootNode.putArray("relyingParties");
        metadataMap.values().stream()
            .filter(meta -> meta.rp != null && meta.rp.get("id") != null)
            .map(meta -> (String) meta.rp.get("id"))
            .distinct()
            .sorted()
            .forEach(rpArray::add);
        
        // Add detailed credential information
        ArrayNode credentialsArray = rootNode.putArray("credentials");
        for (Map.Entry<String, CredentialMetadata> entry : metadataMap.entrySet()) {
            String credentialId = entry.getKey();
            CredentialMetadata metadata = entry.getValue();
            
            // Create a credential JSON object
            ObjectNode credentialNode = credentialsArray.addObject();
            credentialNode.put("id", credentialId);
            
            // Basic metadata
            if (metadata.createdAt > 0) {
                String formattedDate = formatTimestamp(metadata.createdAt);
                credentialNode.put("createdAt", formattedDate);
            }
            
            // Add sign count if available from credential store
            try {
                ByteArray credId = new ByteArray(java.util.Base64.getUrlDecoder().decode(credentialId));
                long signCount = credentialStore.getSignCount(credId);
                credentialNode.put("signCount", signCount);
            } catch (Exception e) {
                credentialNode.put("signCount", 0);
            }
            
            // Algorithm information - might be included in rp or user maps in some implementations
            
            // Relying Party information
            if (metadata.rp != null) {
                ObjectNode rpNode = credentialNode.putObject("relyingParty");
                metadata.rp.forEach((key, value) -> rpNode.put(key, value.toString()));
            }
            
            // User information
            if (metadata.user != null) {
                ObjectNode userNode = credentialNode.putObject("user");
                metadata.user.forEach((key, value) -> userNode.put(key, value.toString()));
            }
            
            // Public key information
            if (verboseOutput) {
                try {
                    ByteArray credId = new ByteArray(java.util.Base64.getUrlDecoder().decode(credentialId));
                    boolean hasKey = credentialStore.hasCredential(credId);
                    
                    if (hasKey) {
                        credentialNode.put("hasPublicKey", true);
                        
                        // Add PEM public key if available
                        if (metadata.publicKeyPem != null) {
                            credentialNode.put("publicKeyPem", metadata.publicKeyPem);
                        }
                    } else {
                        credentialNode.put("publicKeyStatus", "Not found in keystore");
                    }
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Error checking credential " + credentialId, e);
                    credentialNode.put("publicKeyStatus", "Error: " + e.getMessage());
                }
            }
        }
        
        // Add configuration information if verbose
        if (verboseOutput) {
            ObjectNode configNode = rootNode.putObject("configuration");
            try {
                // Obtener información detallada de la configuración del almacén de credenciales
                if (credentialStore instanceof com.example.storage.KeyStoreManager) {
                    com.example.storage.KeyStoreManager ksm = (com.example.storage.KeyStoreManager) credentialStore;
                    
                    // Información de almacenamiento
                    ObjectNode storageNode = configNode.putObject("storage");
                    storageNode.put("keystorePath", ksm.getKeystorePath());
                    storageNode.put("metadataPath", ksm.getMetadataPath());
                    
                    // Información de tiempos de actualización
                    ObjectNode timingNode = configNode.putObject("timing");
                    timingNode.put("lastKeystoreUpdate", formatTimestamp(ksm.getLastKeystoreUpdate()));
                    timingNode.put("lastMetadataUpdate", formatTimestamp(ksm.getLastMetadataUpdate()));
                    
                    // Verificar si los archivos existen físicamente
                    ObjectNode filesNode = configNode.putObject("fileStatus");
                    File keystoreFile = new File(ksm.getKeystorePath());
                    File metadataFile = new File(ksm.getMetadataPath());
                    
                    filesNode.put("keystoreExists", keystoreFile.exists());
                    filesNode.put("metadataExists", metadataFile.exists());
                    
                    if (keystoreFile.exists()) {
                        filesNode.put("keystoreSize", keystoreFile.length() + " bytes");
                        filesNode.put("keystoreLastModified", formatTimestamp(keystoreFile.lastModified()));
                    }
                    
                    if (metadataFile.exists()) {
                        filesNode.put("metadataSize", metadataFile.length() + " bytes");
                        filesNode.put("metadataLastModified", formatTimestamp(metadataFile.lastModified()));
                    }
                }
                
                // Añadir información del sistema
                ObjectNode systemNode = configNode.putObject("system");
                systemNode.put("javaVersion", System.getProperty("java.version"));
                systemNode.put("osName", System.getProperty("os.name"));
                systemNode.put("osVersion", System.getProperty("os.version"));
                systemNode.put("userHome", System.getProperty("user.home"));
                systemNode.put("currentTime", formatTimestamp(System.currentTimeMillis()));
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "Could not add detailed configuration information", e);
                configNode.put("error", "Error gathering configuration details: " + e.getMessage());
            }
        }
        
        return jsonMapper.writeValueAsString(rootNode);
    }
    
    /**
     * Formats a Unix timestamp as a human-readable date.
     * 
     * @param timestamp The timestamp in milliseconds since the epoch
     * @return A formatted date string
     */
    private String formatTimestamp(Long timestamp) {
        if (timestamp == null) return "unknown";
        
        Instant instant = Instant.ofEpochMilli(timestamp);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());
        return formatter.format(instant);
    }
}
