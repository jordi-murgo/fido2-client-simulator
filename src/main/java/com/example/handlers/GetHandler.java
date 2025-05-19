package com.example.handlers;

import com.example.config.CommandOptions;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.example.storage.CredentialMetadata;
import com.example.storage.CredentialStore;
import com.example.utils.EncodingUtils;
import com.example.utils.HashUtils;
import com.example.utils.SignatureUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import lombok.extern.slf4j.Slf4j;

/**
 * Handles the FIDO2 authentication (get) operation, simulating an authenticator's credential usage.
 */
@Slf4j
public class GetHandler extends BaseHandler implements CommandHandler {
    @Override
    public String handleRequest(String requestJson) throws Exception {
        return handleGet(requestJson);
    }
    /**
     * Constructs a GetHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param options The command line options
     */
    public GetHandler(CredentialStore credentialStore, ObjectMapper jsonMapper, CommandOptions options) {
        super(credentialStore, jsonMapper, options);
    }

    /**
     * Handles the authentication of a FIDO2 credential, returning the PublicKeyCredential as JSON.
     * <p>
     * This method simulates an authenticator performing the following steps:
     * 1. Select a credential based on the provided options
     * 2. Generate authenticator data (RP ID hash, flags, counter)
     * 3. Create client data JSON with proper challenge and origin
     * 4. Sign the concatenation of authenticator data and client data hash
     * 5. Format the response according to the requested format
     * </p>
     * 
     * @param optionsJson JSON string for PublicKeyCredentialRequestOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleGet(String optionsJson) throws Exception {
        try {
            log.debug("Handling get request with format: {}", formatter.getFormatName());
            
            // Decode and ensure extensions are present
            optionsJson = EncodingUtils.tryDecodeBase64Json(optionsJson);
            optionsJson = ensureExtensionsInJson(optionsJson);
            
            // Parse options
            PublicKeyCredentialRequestOptions options = jsonMapper.readValue(optionsJson, PublicKeyCredentialRequestOptions.class);
            options = ensureExtensions(options);

            // 1. Select a credential
            ByteArray credentialId = selectCredential(options);
            
            // 2. Get private key from keystore
            PrivateKey privateKey = credentialStore.getPrivateKey(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("No private key found for credential ID: " + credentialId.getBase64Url()));
            
            // 3. Create authenticator data
            byte[] authenticatorData = createAuthenticatorData(options, credentialId);
            
            // 4. Create client data JSON
            String clientDataJson = createClientDataJson(options);
            
            // 5. Generate signature
            byte[] signature = generateSignature(authenticatorData, clientDataJson, privateKey);
            
            // Initialize the response formatter
            log.debug("Using response format: {}", formatter.getFormatName());
            
            // Create credential node with all expected fields (WebAuthn spec)
            ObjectNode credentialNode = jsonMapper.createObjectNode();
            
            // Format credential ID according to the configuration
            formatter.formatBytes(credentialNode, "id", credentialId);
            formatter.formatBytes(credentialNode, "rawId", credentialId);
            
            // Set the credential type
            credentialNode.put("type", "public-key");
            
            // Add empty clientExtensionResults at root
            ObjectNode clientExtResults = jsonMapper.createObjectNode();
            credentialNode.set("clientExtensionResults", clientExtResults);
            
            // Build response node with all expected fields
            ObjectNode responseNode = jsonMapper.createObjectNode();
            
            // Format clientDataJSON according to the configuration
            formatter.formatBytes(responseNode, "clientDataJSON", new ByteArray(clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            
            // Format authenticatorData according to the configuration
            formatter.formatBytes(responseNode, "authenticatorData", new ByteArray(authenticatorData));
            
            // Format signature according to the configuration
            formatter.formatBytes(responseNode, "signature", new ByteArray(signature));
            
            // Add userHandle if available
            Optional<ByteArray> userHandle = credentialStore.getUserHandleForCredential(credentialId);
            if (userHandle.isPresent() && !userHandle.get().isEmpty()) {
                formatter.formatBytes(responseNode, "userHandle", userHandle.get());
            }
            
            // Set the response node in the credential node
            credentialNode.set("response", responseNode);
            
            // Convert to JSON string
            return removeNulls(credentialNode.toString());
        } catch (Exception e) {
            log.debug("Error during authentication", e);
            throw new Exception("Error during authentication: " + e.getMessage(), e);
        }
    }

    private ByteArray selectCredential(PublicKeyCredentialRequestOptions requestOptions) {
        Optional<List<PublicKeyCredentialDescriptor>> allowedCredentialsOpt = requestOptions.getAllowCredentials();
        List<PublicKeyCredentialDescriptor> allowedCredentials = allowedCredentialsOpt.orElse(List.of());
        List<ByteArray> availableCredentialIds = credentialStore.getCredentialIdsForRpId(requestOptions.getRpId());
        
        List<ByteArray> matchingCredentialIds = availableCredentialIds.stream()
            .filter(id -> allowedCredentials.isEmpty() || 
                   allowedCredentials.stream().anyMatch(cred -> cred.getId().equals(id)))
            .collect(Collectors.toList());
        
        if (matchingCredentialIds.isEmpty()) {
            throw new IllegalStateException("No matching credentials found");
        }
        
        if (this.options.isInteractive() && matchingCredentialIds.size() > 1) {
            return promptForCredentialSelection(matchingCredentialIds);
        }
        
        // If we have multiple credentials but not in interactive mode, just return the first one
        if (!this.options.isInteractive()) {
            System.out.println("Multiple credentials found, automatically selecting the first one (non-interactive mode)");
            return matchingCredentialIds.get(0);
        }
        
        return promptForCredentialSelection(matchingCredentialIds);
    }

    private ByteArray promptForCredentialSelection(List<ByteArray> credentialIds) {
        Map<String, CredentialMetadata> metadataMap = credentialStore.getMetadataMap();
        
        System.out.println("\nAvailable credentials:");
        // Print header row for the table
        System.out.println("-----------------------------------------------------------------------------------------");
        System.out.println("  IDX | CREDENTIAL ID          | CREATION TIMESTAMP  | CNT | USER INFO");
        System.out.println("-----------------------------------------------------------------------------------------");
        
        for (int i = 0; i < credentialIds.size(); i++) {
            String credId = credentialIds.get(i).getBase64Url();
            // Get user info from metadata
            String userInfo = "Unknown user";
            String createdAt = "N/A";
            String signCount = "0";
            
            if (metadataMap.containsKey(credId)) {
                CredentialMetadata metadata = metadataMap.get(credId);
                
                // Format creation date/time
                if (metadata.createdAt > 0) {
                    createdAt = formatDatetime(metadata.createdAt);
                }
                
                // Get sign count
                if (metadata.user != null && metadata.user.containsKey("signCount")) {
                    signCount = metadata.user.get("signCount").toString();
                }
                
                // Get user info
                if (metadata.user != null) {
                    String userName = metadata.user.containsKey("name") ? 
                            metadata.user.get("name").toString() : "unknown";
                    String displayName = metadata.user.containsKey("displayName") ? 
                            metadata.user.get("displayName").toString() : "";
                    
                    userInfo = userName;
                    if (!displayName.isEmpty() && !displayName.equals(userName)) {
                        userInfo += " (" + displayName + ")";
                    }
                }
            }
            
            // Format the credential ID to ensure consistent width
            String formattedCredId = credId;
            if (formattedCredId.length() > 30) {
                formattedCredId = formattedCredId.substring(0, 30);
            } else {
                formattedCredId = String.format("%-13s", formattedCredId);
            }
            
            System.out.println(String.format("  [%d] | %s | %s | %3s | %s", 
                i+1, formattedCredId, createdAt, signCount, userInfo));
        }
        System.out.println("-----------------------------------------------------------------------------------------");
        
        System.out.print("Select credential (1-" + credentialIds.size() + "): ");
        int selection = 1; // Default to first credential
        
        try {
            // Usar una forma más robusta de leer la entrada que funcione en diversos contextos
            String input = null;
            // Intentar usar console primero (funciona bien en terminal interactiva)
            if (System.console() != null) {
                input = System.console().readLine();
            } else {
                // Fallback a BufferedReader si console no está disponible
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    input = reader.readLine();
                }
            }
            
            if (input != null && !input.trim().isEmpty()) {
                selection = Integer.parseInt(input.trim());
                if (selection < 1 || selection > credentialIds.size()) {
                    System.out.println("Invalid selection, using first credential.");
                    selection = 1;
                }
            } else {
                System.out.println("No selection made, using first credential.");
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input, using first credential.");
        } catch (IOException e) {
            System.out.println("Error reading input: " + e.getMessage() + ", using first credential.");
        }
        
        ByteArray selectedCredential = credentialIds.get(selection - 1);
        System.out.println("Selected credential: " + selectedCredential.getBase64Url());
        return selectedCredential;
    }

    private byte[] createAuthenticatorData(PublicKeyCredentialRequestOptions requestOptions, ByteArray credentialId) throws Exception {
        // Get the RP ID hash
        byte[] rpIdHash = HashUtils.sha256(requestOptions.getRpId());
        
        // Set the flags (UP=1)
        byte flags = (byte) 0x01; // User Present = true
        
        // Get the signature counter using functional approach
        long signCount = credentialStore.incrementAndSaveSignCount(credentialId);
        
        // Compose the authenticator data
        return composeAuthenticatorData(rpIdHash, flags, signCount);
    }
    
    private String createClientDataJson(PublicKeyCredentialRequestOptions requestOptions) {
        // Get the challenge in base64url format and ensure it's not escaped in JSON
        String challenge = requestOptions.getChallenge().getBase64Url();
        
        // Create a raw JSON string to prevent escaping of the challenge
        String clientDataJson = String.format(
            "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"https://%s\"}",
            challenge,
            requestOptions.getRpId()
        );
        
        log.debug("Created client data JSON with origin: https://{} and challenge: {}", requestOptions.getRpId(), challenge);
        return clientDataJson;
    }
    
    private byte[] generateSignature(byte[] authenticatorData, String clientDataJson, PrivateKey privateKey) throws Exception {
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        return SignatureUtils.sign(dataToSign, privateKey);
    }

    // Estos métodos ya no son necesarios después de la refactorización del método handleGet
    // Los métodos createAssertionResponse y createCredential se han eliminado porque ahora construimos
    // directamente los nodos JSON con el formatter

    private static byte[] composeAuthenticatorData(byte[] rpIdHash, byte flags, long signCount) {
        byte[] signCountBytes = ByteBuffer.allocate(4).putInt((int) signCount).array();
        
        byte[] out = new byte[37];
        System.arraycopy(rpIdHash, 0, out, 0, 32);
        out[32] = flags;
        System.arraycopy(signCountBytes, 0, out, 33, 4);
        
        return out;
    }
    
    /**
     * Formats a Unix timestamp (in milliseconds) to a human-readable date format yyyy-MM-dd HH:mm
     * 
     * @param timestamp The Unix timestamp in milliseconds
     * @return Formatted date string
     */
    private String formatDatetime(long timestamp) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(new Date(timestamp));
    }
}
