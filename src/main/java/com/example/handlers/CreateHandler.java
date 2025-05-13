package com.example.handlers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.util.Map;

import com.example.storage.CredentialMetadata;
import com.example.storage.CredentialStore;
import com.example.storage.KeyStoreManager;
import com.example.utils.HashUtils;
import com.example.utils.AuthDataUtils;
import com.example.utils.PemUtils;
import com.example.utils.CoseKeyUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;

/**
 * Handles the FIDO2 registration (create) operation, simulating an authenticator's credential creation.
 */
public class CreateHandler extends BaseHandler implements CredentialHandler {
    private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger(CreateHandler.class.getName());

    @Override
    public String handleRequest(String requestJson) throws Exception {
        return handleCreate(requestJson);
    }

    private static final ByteArray AAGUID = new ByteArray(new byte[16]); // Zero AAGUID for software authenticator

    /**
     * Constructs a CreateHandler.
     * @param credentialStore The KeyStoreManager instance
     * @param jsonMapper The Jackson ObjectMapper
     */
    /**
     * Constructs a CreateHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     */
    public CreateHandler(CredentialStore credentialStore, ObjectMapper jsonMapper) {
        super(credentialStore, jsonMapper);
    }

    /**
     * Handles the creation of a new FIDO2 credential, returning the PublicKeyCredential as JSON.
     * @param optionsJson JSON string for PublicKeyCredentialCreationOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleCreate(String optionsJson) throws Exception {
        try {
            optionsJson = tryDecodeBase64Json(optionsJson);
            PublicKeyCredentialCreationOptions options = jsonMapper.readValue(optionsJson, PublicKeyCredentialCreationOptions.class);
            validateOptions(options);
    
            // 1. Select an algorithm (first supported)
            COSEAlgorithmIdentifier selectedAlg = selectAlgorithm(options);
            
            // 2. Generate credential ID and key pair
            ByteArray credentialId = KeyStoreManager.generateRandomCredentialId();
            KeyPair keyPair = credentialStore.generateAndStoreKeyPair(credentialId, options.getUser().getId(), selectedAlg);
            
            // 3. Create attestation object
            byte[] attestationObject = createAttestationObject(options, credentialId, keyPair.getPublic(), selectedAlg);
            
            // 4. Create client data JSON
            String clientDataJson = createClientDataJson(options);
            
            // 5. Create response
            AuthenticatorAttestationResponse response = createAttestationResponse(attestationObject, clientDataJson);
            
            // 6 y 7. Crear respuesta JSON directamente (evitando PublicKeyCredential que puede causar UnsupportedOperationException)
            // Construimos el JSON manualmente para evitar problemas de serialización con objetos complejos
            ObjectNode credentialNode = jsonMapper.createObjectNode();
            credentialNode.put("id", credentialId.getBase64Url());
            credentialNode.put("rawId", credentialId.getBase64Url());
            credentialNode.put("type", "public-key");
            
            ObjectNode responseNode = jsonMapper.createObjectNode();
            responseNode.put("clientDataJSON", response.getClientDataJSON().getBase64Url());
            responseNode.put("attestationObject", response.getAttestationObject().getBase64Url());
            
            credentialNode.set("response", responseNode);
            
            // Crear JSON de respuesta
            String registrationResponseJson = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(credentialNode);
            
            // 8. Log attestation object details
            logAttestationObject(registrationResponseJson);
            
            // 9. Save metadata
            saveMetadata(credentialId, registrationResponseJson, options);
            
            // 10. Add rawId and return
            try {
                return addRawIdToResponse(registrationResponseJson);
            } catch (UnsupportedOperationException uoe) {
                uoe.printStackTrace(); // Imprimir el stack trace completo para localizar el origen exacto
                // Crear respuesta de error con detalles para ayudar en la depuración
                ObjectNode errorNode = jsonMapper.createObjectNode();
                errorNode.put("status", "error");
                errorNode.put("error", "UnsupportedOperationException");
                errorNode.put("message", uoe.getMessage() != null ? uoe.getMessage() : "No message");
                errorNode.put("location", "Ocurrió en: " + uoe.getStackTrace()[0]);
                
                return jsonMapper.writeValueAsString(errorNode); // Devolver JSON de error en lugar de lanzar excepción
            }
        } catch (IOException | KeyStoreException e) {
            e.printStackTrace(); // Imprimir el stack trace para depuración
            throw new Exception("Error durante la creación de credenciales: " + e.getMessage(), e);
        } catch (Exception ex) {
            ex.printStackTrace(); // Imprimir cualquier otra excepción
            throw new Exception("Error inesperado: " + ex.getMessage(), ex);
        }
    }

    private void validateOptions(PublicKeyCredentialCreationOptions options) {
        if (options.getPubKeyCredParams().isEmpty()) {
            throw new IllegalArgumentException("No supported algorithms provided");
        }
    }

    private COSEAlgorithmIdentifier selectAlgorithm(PublicKeyCredentialCreationOptions options) {
        return options.getPubKeyCredParams().stream()
            .map(PublicKeyCredentialParameters::getAlg)
            .filter(alg -> alg == COSEAlgorithmIdentifier.ES256 || alg == COSEAlgorithmIdentifier.RS256)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("No supported algorithm found (ES256 or RS256)"));
    }

    private byte[] createAttestationObject(PublicKeyCredentialCreationOptions options, ByteArray credentialId, 
                                         PublicKey publicKey, COSEAlgorithmIdentifier selectedAlg) throws Exception {
        // Generate authenticator data
        byte[] rpIdHash = HashUtils.sha256(options.getRp().getId().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte flags = (byte) 0x41; // UP and AT flags
        long signCount = 0;
        ByteArray cosePublicKey = CoseKeyUtils.encodeToCose(publicKey, selectedAlg);
        
        byte[] authData = composeAuthenticatorDataWithAttestedCredentialData(
            rpIdHash, flags, signCount, AAGUID, credentialId, cosePublicKey);
        
        // Create attestation object as CBOR map with format "none" (no attestation)
        com.fasterxml.jackson.dataformat.cbor.CBORFactory cborFactory = 
            new com.fasterxml.jackson.dataformat.cbor.CBORFactory();
        com.fasterxml.jackson.databind.ObjectMapper cborWriter = 
            new com.fasterxml.jackson.databind.ObjectMapper(cborFactory);
        
        // Create a map with the required fields for an attestation object
        java.util.Map<String, Object> attestationObject = new java.util.LinkedHashMap<>();
        attestationObject.put("fmt", "none");  // Use "none" attestation format
        attestationObject.put("authData", authData);
        attestationObject.put("attStmt", new java.util.LinkedHashMap<>()); // Empty attestation statement
        
        // Encode the map to CBOR
        return cborWriter.writeValueAsBytes(attestationObject);
    }

    private String createClientDataJson(PublicKeyCredentialCreationOptions options) throws JsonProcessingException {
        ObjectNode clientData = jsonMapper.createObjectNode();
        clientData.put("type", "webauthn.create");
        clientData.put("challenge", options.getChallenge().getBase64Url());
        clientData.put("origin", "https://" + options.getRp().getId());
        return jsonMapper.writeValueAsString(clientData);
    }

    /**
     * Creates an AuthenticatorAttestationResponse from attestation object and client data JSON.
     * @param attestationObject The attestation object bytes
     * @param clientDataJson The client data JSON string
     * @return The attestation response
     */
    private AuthenticatorAttestationResponse createAttestationResponse(byte[] attestationObject, String clientDataJson) {
        try {
            // Convert raw bytes directly - no intermediate conversions
            ByteArray attestationByteArray = new ByteArray(attestationObject);
            
            // For client data JSON, ensure proper encoding
            byte[] clientDataJsonBytes = clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ByteArray clientDataJsonByteArray = new ByteArray(clientDataJsonBytes);
            
            return AuthenticatorAttestationResponse.builder()
                .attestationObject(attestationByteArray)
                .clientDataJSON(clientDataJsonByteArray)
                .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Error creating attestation response: " + e.getMessage(), e);
        }
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> createCredential(
            ByteArray credentialId, AuthenticatorAttestationResponse response) {
        return PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
            .id(credentialId)
            .response(response)
            .clientExtensionResults(ClientRegistrationExtensionOutputs.builder().build())
            .build();
    }

    private void logAttestationObject(String registrationResponseJson) {
        try {
            ObjectNode responseNode = jsonMapper.readTree(registrationResponseJson).get("response").deepCopy();
            String attestationB64 = responseNode.get("attestationObject").asText();
            byte[] attestationBytes = java.util.Base64.getUrlDecoder().decode(attestationB64);
            
            com.fasterxml.jackson.dataformat.cbor.CBORFactory cborFactory = new com.fasterxml.jackson.dataformat.cbor.CBORFactory();
            com.fasterxml.jackson.databind.ObjectMapper cborReader = new com.fasterxml.jackson.databind.ObjectMapper(cborFactory);
            com.fasterxml.jackson.databind.JsonNode cborData = cborReader.readTree(attestationBytes);
            
            System.out.println("=== AttestationObject (decoded) ===");
            System.out.println("fmt: " + cborData.get("fmt"));
            
            byte[] rawAuthData = cborData.get("authData").binaryValue();
            System.out.println("authData (base64): " + java.util.Base64.getEncoder().encodeToString(rawAuthData));
            
            System.out.println("\n--- AuthData Structure ---");
            System.out.println(AuthDataUtils.decodeAuthData(rawAuthData));
            System.out.println("------------------------");
            
            System.out.println("attStmt: " + cborData.get("attStmt"));
            System.out.println("==============================");
        } catch (Exception e) {
            System.out.println("[WARN] Could not decode attestationObject: " + e.getMessage());
        }
    }

    /**
     * Saves credential metadata.
     * @param credentialId The credential ID
     * @param registrationResponseJson The registration response JSON
     * @param options The creation options
     * @throws KeyStoreException if an error occurs with the keystore
     */
    /**
     * Saves credential metadata.
     * @param credentialId The credential ID
     * @param registrationResponseJson The registration response JSON
     * @param options The creation options
     * @throws KeyStoreException if an error occurs with the keystore
     */
    private void saveMetadata(ByteArray credentialId, String registrationResponseJson, 
                            PublicKeyCredentialCreationOptions options) throws KeyStoreException {
        if (credentialStore != null) {
            try {
                CredentialMetadata meta = new CredentialMetadata();
                meta.credentialId = credentialId.getBase64Url();
                meta.registrationResponseJson = registrationResponseJson;
                meta.createdAt = System.currentTimeMillis();
                meta.rp = jsonMapper.convertValue(options.getRp(), 
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
                meta.user = jsonMapper.convertValue(options.getUser(), 
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
                
                try {
                    // Usar Optional para obtener la clave pública
                    meta.publicKeyPem = credentialStore.getPublicKey(credentialId)
                        .map(PemUtils::publicKeyToPem)
                        .orElse(null);
                } catch (KeyStoreException e) {
                    meta.publicKeyPem = null;
                }
                
                // Usar el nuevo método addCredentialMetadata() en lugar de intentar modificar el mapa directamente
                credentialStore.addCredentialMetadata(meta.credentialId, meta);
                credentialStore.saveMetadata();
            } catch (IOException e) {
                throw new KeyStoreException("Failed to save metadata: " + e.getMessage(), e);
            }
        }
    }

    private static byte[] composeAuthenticatorDataWithAttestedCredentialData(
            byte[] rpIdHash, byte flags, long signCount, ByteArray aaguid, 
            ByteArray credentialId, ByteArray cosePublicKey) {
        byte[] aaguidBytes = aaguid.getBytes();
        byte[] credIdBytes = credentialId.getBytes();
        byte[] coseBytes = cosePublicKey.getBytes();
        byte[] lengthBytes = new byte[] { (byte) (credIdBytes.length >> 8), (byte) (credIdBytes.length & 0xFF) };
        byte[] signCountBytes = ByteBuffer.allocate(4).putInt((int) signCount).array();
        
        int total = 32 + 1 + 4 + 16 + 2 + credIdBytes.length + coseBytes.length;
        byte[] out = new byte[total];
        int offset = 0;
        
        System.arraycopy(rpIdHash, 0, out, offset, 32); offset += 32;
        out[offset++] = flags;
        System.arraycopy(signCountBytes, 0, out, offset, 4); offset += 4;
        System.arraycopy(aaguidBytes, 0, out, offset, 16); offset += 16;
        System.arraycopy(lengthBytes, 0, out, offset, 2); offset += 2;
        System.arraycopy(credIdBytes, 0, out, offset, credIdBytes.length); offset += credIdBytes.length;
        System.arraycopy(coseBytes, 0, out, offset, coseBytes.length);
        
        return out;
    }
}
