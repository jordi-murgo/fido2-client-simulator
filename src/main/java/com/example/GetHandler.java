package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.List;

/**
 * Handles the FIDO2 authentication (get) operation, simulating an authenticator's assertion response.
 */
public class GetHandler {

    private final KeyStoreManager keyStoreManager;
    private final ObjectMapper jsonMapper;
    private final boolean interactive;

    /**
     * Constructs a GetHandler.
     * @param keyStoreManager The KeyStoreManager instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param interactive If true, prompt user for credential selection when multiple exist
     */
    public GetHandler(KeyStoreManager keyStoreManager, ObjectMapper jsonMapper, boolean interactive) {
        this.keyStoreManager = keyStoreManager;
        this.jsonMapper = jsonMapper;
        this.interactive = interactive;
    }

    /**
     * Handles the assertion (get) operation, returning the PublicKeyCredential as JSON.
     * If allowCredentials is missing or empty, all credentials for the rpId are considered.
     * If multiple credentials exist and interactive=true, prompts user to select.
     * Otherwise, selects the first credential and prints a warning.
     * @param optionsJson JSON string for PublicKeyCredentialRequestOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleGet(String optionsJson) throws Exception {
        // Attempt to decode Base64-encoded JSON (supports URL-safe and standard Base64)
        optionsJson = Util.tryDecodeBase64Json(optionsJson);

        PublicKeyCredentialRequestOptions options = jsonMapper.readValue(optionsJson, PublicKeyCredentialRequestOptions.class);
        List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials().orElse(null);
        ByteArray credentialId = null;

        if (allowCredentials == null || allowCredentials.isEmpty()) {
            // No allowCredentials: get all credentials for rpId
            List<ByteArray> creds = keyStoreManager.getCredentialIdsForRpId(options.getRpId());
            if (creds.isEmpty()) {
                throw new IllegalArgumentException("No credentials found for rpId: " + options.getRpId());
            } else if (creds.size() == 1) {
                credentialId = creds.get(0);
                System.out.println("[INFO] Only one credential found for rpId '" + options.getRpId() + "'. Using: " + credentialId.getBase64Url());
            } else {
                // Si el flag interactive està activat, sempre intentem fer el prompt
                if (interactive) {
                    // Mode interactiu: mostrar opcions i demanar selecció
                    System.out.println("[INFO] Multiple credentials found for rpId '" + options.getRpId() + "':");
                    System.out.println("--------------------------------------------------------------");
                    System.out.println("  IDX | CREDENTIAL ID                  | USER INFO");
                    System.out.println("--------------------------------------------------------------");
                    for (int i = 0; i < creds.size(); i++) {
                        ByteArray credId = creds.get(i);
                        // Obtenir la informació d'usuari per a aquesta credencial
                        java.util.Map<String, String> userInfo = keyStoreManager.getUserInfoForCredential(credId);
                        String userName = "<unknown>";
                        String displayName = "<unknown>";
                        
                        if (userInfo != null) {
                            userName = userInfo.get("name");
                            displayName = userInfo.get("displayName");
                        }
                        
                        // Formatar la sortida amb alineació de columnes
                        String credIdShort = credId.getBase64Url();
                        if (credIdShort.length() > 30) {
                            credIdShort = credIdShort.substring(0, 27) + "...";
                        }
                        
                        System.out.printf("  [%d] | %-30s | %s (%s)%n", 
                                i, credIdShort, userName, displayName);
                    }
                    System.out.println("--------------------------------------------------------------");
                    
                    int idx = -1;
                    System.out.print("Select credential index: ");
                    System.out.flush(); // Assegurar que el prompt es mostra
                    
                    // Utilitzem Console si està disponible (millor per a passwords i interacció)
                    // o Scanner com a fallback
                    if (System.console() != null) {
                        while (idx < 0 || idx >= creds.size()) {
                            String input = System.console().readLine();
                            try {
                                idx = Integer.parseInt(input);
                                if (idx < 0 || idx >= creds.size()) {
                                    System.out.print("Invalid index. Try again: ");
                                    System.out.flush();
                                }
                            } catch (NumberFormatException e) {
                                System.out.print("Invalid input. Enter a number: ");
                                System.out.flush();
                            }
                        }
                    } else {
                        // Fallback a Scanner si Console no està disponible
                        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
                            while (idx < 0 || idx >= creds.size()) {
                                if (scanner.hasNextLine()) {
                                    String input = scanner.nextLine();
                                    try {
                                        idx = Integer.parseInt(input);
                                        if (idx < 0 || idx >= creds.size()) {
                                            System.out.print("Invalid index. Try again: ");
                                            System.out.flush();
                                        }
                                    } catch (NumberFormatException e) {
                                        System.out.print("Invalid input. Enter a number: ");
                                        System.out.flush();
                                    }
                                } else {
                                    // Si no hi ha més input disponible, sortim del bucle i usem el primer
                                    System.out.println("\n[WARN] No input available. Using the first credential.");
                                    idx = 0;
                                    break;
                                }
                            }
                        }
                    }
                    
                    credentialId = creds.get(idx);
                    System.out.println("[INFO] Selected credential: " + credentialId.getBase64Url());
                } else {
                    // Mode no interactiu o no es pot fer prompt: usar el primer i mostrar advertència
                    credentialId = creds.get(0);
                    if (interactive) {
                        System.out.println("[WARN] Multiple credentials found for rpId '" + options.getRpId() + "'. Using the first: " + credentialId.getBase64Url() + ". (--interactive flag detected but input is not from a terminal)");
                    } else {
                        System.out.println("[WARN] Multiple credentials found for rpId '" + options.getRpId() + "'. Using the first: " + credentialId.getBase64Url() + ". Use --interactive for manual selection.");
                    }
                }
            }
        } else {
            credentialId = allowCredentials.get(0).getId();
            // Verificar si la credencial existe en el keystore
            if (!keyStoreManager.hasCredential(credentialId)) {
                throw new IllegalArgumentException("Credential ID not found: " + credentialId.getBase64Url() + ". The credential may have been deleted or never existed.");
            }
        }

        // Verificar nuevamente que la credencial existe
        if (!keyStoreManager.hasCredential(credentialId)) {
            throw new IllegalArgumentException("Credential ID not found: " + credentialId.getBase64Url() + ". The credential may have been deleted or never existed.");
        }
        
        PublicKey publicKey = keyStoreManager.getPublicKey(credentialId);
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key not found for credential ID: " + credentialId.getBase64Url());
        }
        
        PrivateKey privateKey = keyStoreManager.getPrivateKey(credentialId);
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key not found for credential ID: " + credentialId.getBase64Url());
        }
        
        ByteArray userHandle = keyStoreManager.getUserHandleForCredential(credentialId);
        long signCount = keyStoreManager.getSignCount(credentialId);

        // 2. Prepare authenticator data
        byte[] rpIdHash = Util.sha256(options.getRpId());
        byte flags = (byte) 0b00000001; // UP=1, AT=0 (no attestedCredentialData para autenticación)
        if (options.getUserVerification().orElse(UserVerificationRequirement.DISCOURAGED) == UserVerificationRequirement.REQUIRED) {
            flags |= (byte) 0b00000100; // Set UV bit
        }
        signCount++;
        // keyStoreManager.setSignCount(credentialId, signCount); // Uncomment if you want to persist signCount

        // Compose authenticator data bytes (no attestedCredentialData for assertion)
        ByteBuffer authDataBuf = ByteBuffer.allocate(32 + 1 + 4);
        authDataBuf.put(rpIdHash);
        authDataBuf.put(flags);
        authDataBuf.putInt((int) signCount);
        
        // Crear ByteArray para autenticación - no intentamos parsear como AuthenticatorData
        ByteArray authDataBytes = new ByteArray(authDataBuf.array());
        
        // NOTA: En lugar de construir un objeto AuthenticatorData completo,
        // simplemente pasamos los bytes directamente a la respuesta de autenticación

        // 4. Construct clientDataJSON
        ObjectNode clientData = jsonMapper.createObjectNode();
        clientData.put("type", "webauthn.get");
        clientData.put("challenge", options.getChallenge().getBase64Url());
        clientData.put("origin", "https://" + options.getRpId());
        String clientDataJsonString = jsonMapper.writeValueAsString(clientData);
        ByteArray clientDataJsonBytes = new ByteArray(clientDataJsonString.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ByteArray clientDataHash = new ByteArray(Util.sha256(clientDataJsonBytes.getBytes()));

        // 5. Create Signature
        ByteBuffer signedData = ByteBuffer.allocate(authDataBytes.size() + clientDataHash.size());
        signedData.put(authDataBytes.getBytes());
        signedData.put(clientDataHash.getBytes());

        COSEAlgorithmIdentifier alg = determineAlgorithmFromKey(publicKey);
        Signature signature = Signature.getInstance(getSignatureAlgorithm(alg), KeyStoreManager.PROVIDER);
        signature.initSign(privateKey);
        signature.update(signedData.array());
        ByteArray assertionSignature = new ByteArray(signature.sign());

        // 6. Retrieve userHandle
        // ByteArray userHandle = keyStoreManager.getUserHandleForCredential(credentialId);

        // 7. Assemble PublicKeyCredential
        AuthenticatorAssertionResponse response = AuthenticatorAssertionResponse.builder()
                .authenticatorData(authDataBytes)
                .clientDataJSON(clientDataJsonBytes)
                .signature(assertionSignature)
                .userHandle(userHandle)
                .build();

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                    .id(credentialId)
                    .response(response)
                    .clientExtensionResults(ClientAssertionExtensionOutputs.builder().build())
                    .build();

        return jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(credential);
    }

    private COSEAlgorithmIdentifier determineAlgorithmFromKey(PublicKey publicKey) {
        if ("EC".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return COSEAlgorithmIdentifier.ES256;
        } else if ("RSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return COSEAlgorithmIdentifier.RS256;
        }
        throw new IllegalArgumentException("Unsupported public key algorithm: " + publicKey.getAlgorithm());
    }

    private String getSignatureAlgorithm(COSEAlgorithmIdentifier coseAlg) {
        if (COSEAlgorithmIdentifier.ES256.equals(coseAlg)) {
            return "SHA256withECDSA";
        } else if (COSEAlgorithmIdentifier.RS256.equals(coseAlg)) {
            return "SHA256withRSA";
        }
        throw new IllegalArgumentException("Unsupported COSE algorithm for JCA signature: " + coseAlg);
    }
    
    // S'ha eliminat el mètode isInputAvailable() ja que no s'utilitza
}
