package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ByteArray;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

/**
 * Manages the Java KeyStore (JKS) for FIDO2 credential key pairs and a separate properties file for credential metadata.
 * Handles key pair generation, storage, retrieval, and metadata management (signCount, userHandle).
 */
public class KeyStoreManager {
    public static final String KEYSTORE_FILE = "fido2_keystore.p12";
    public static final String METADATA_FILE = "fido2_metadata.json";
    public static final String KEYSTORE_PASSWORD = "changeit"; // For demo only; change in production!
    public static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private KeyStore keyStore;
    public Map<String, CredentialMetadata> metadataMap = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Initializes the KeyStoreManager, loading or creating the keystore and metadata files.
     */
    public final ObjectMapper jsonMapper = new ObjectMapper();

    public void saveMetadata() throws java.io.IOException {
        jsonMapper.writerWithDefaultPrettyPrinter().writeValue(new java.io.File(METADATA_FILE), metadataMap);
    }

    public void loadMetadata() {
        try {
            java.io.File file = new java.io.File(METADATA_FILE);
            if (!file.exists()) {
                metadataMap = new HashMap<>();
            } else {
                metadataMap = jsonMapper.readValue(file, new TypeReference<Map<String, CredentialMetadata>>() {});
            }
        } catch (Exception e) {
            metadataMap = new HashMap<>();
        }
    }

    public KeyStoreManager() {
        loadKeyStore();
        loadMetadata();
    }

    /**
     * Returns a list of credential IDs (ByteArray) associated with the given rpId.
     * @param rpId the relying party ID
     * @return a list of credential IDs (ByteArray)
     */
    public List<ByteArray> getCredentialIdsForRpId(String rpId) {
        List<ByteArray> credentialIds = new ArrayList<>();
        for (Map.Entry<String, CredentialMetadata> entry : metadataMap.entrySet()) {
            CredentialMetadata meta = entry.getValue();
            if (meta.rp != null && rpId.equals(meta.rp.get("id"))) {
                credentialIds.add(new ByteArray(java.util.Base64.getUrlDecoder().decode(meta.credentialId)));
            }
        }
        return credentialIds;
    }

    private void loadKeyStore() {
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            File ksFile = new File(KEYSTORE_FILE);
            if (ksFile.exists()) {
                try (InputStream is = new FileInputStream(ksFile)) {
                    keyStore.load(is, KEYSTORE_PASSWORD.toCharArray());
                }
            } else {
                keyStore.load(null, KEYSTORE_PASSWORD.toCharArray()); // Initialize new keystore
                saveKeyStore(); // Create an empty keystore file
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Failed to load keystore: " + e.getMessage(), e);
        }
    }

    private void saveKeyStore() {
        try (OutputStream os = new FileOutputStream(KEYSTORE_FILE)) {
            keyStore.store(os, KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Failed to save keystore: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a new key pair, stores it in the keystore, and records metadata.
     * @param credentialId Unique credential ID
     * @param userHandle User handle
     * @param alg COSE algorithm identifier
     * @return The generated KeyPair
     * @throws GeneralSecurityException on cryptographic errors
     */
    public KeyPair generateAndStoreKeyPair(ByteArray credentialId, ByteArray userHandle, COSEAlgorithmIdentifier alg)
            throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator;
        String signatureAlgorithm;

        if (COSEAlgorithmIdentifier.ES256.equals(alg)) {
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", PROVIDER);
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            signatureAlgorithm = "SHA256withECDSA";
        } else if (COSEAlgorithmIdentifier.RS256.equals(alg)) {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
            keyPairGenerator.initialize(2048);
            // RSA key algorithm
            signatureAlgorithm = "SHA256withRSA";
        } else {
            throw new NoSuchAlgorithmException("Unsupported algorithm: " + alg);
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        String alias = credentialId.getBase64Url();

        // Create a self-signed certificate to store the public key
        try {
            java.security.cert.Certificate[] chain = { createSelfSignedCertificate(keyPair, signatureAlgorithm, userHandle) };
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), chain);
            saveKeyStore();

             // Store metadata: handled by CreateHandler and metadataMap, nothing to do here

        } catch (Exception e) {
            throw new KeyStoreException("Failed to store key pair: " + e.getMessage(), e);
        }
        return keyPair;
    }

    private Certificate createSelfSignedCertificate(KeyPair keyPair, String sigAlgName, ByteArray userHandle) throws Exception {
        // Simplified self-signed certificate for demonstration
        org.bouncycastle.asn1.x500.X500Name subjectDN = new org.bouncycastle.asn1.x500.X500Name("CN=" + userHandle.getBase64Url());
        java.math.BigInteger serialNumber = java.math.BigInteger.valueOf(System.currentTimeMillis());
        java.util.Date notBefore = new java.util.Date();
        java.util.Date notAfter = new java.util.Date(System.currentTimeMillis() + (10L * 365 * 24 * 60 * 60 * 1000)); // 10 years

        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder certBuilder =
            new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(subjectDN, serialNumber, notBefore, notAfter, subjectDN, keyPair.getPublic());

        org.bouncycastle.operator.ContentSigner contentSigner =
            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgName).build(keyPair.getPrivate());

        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        // Convert the certificate to X509Certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certificateInfo = new ByteArrayInputStream(certHolder.getEncoded());
        Certificate certificate = certificateFactory.generateCertificate(certificateInfo);

        return certificate;
    }

    /**
     * Retrieves the private key for a given credential ID.
     * @param credentialId the credential ID
     * @return the PrivateKey, or null if not found
     */
    public PrivateKey getPrivateKey(ByteArray credentialId) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String alias = credentialId.getBase64Url();
        Key key = keyStore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
        return (key instanceof PrivateKey) ? (PrivateKey) key : null;
    }

    /**
     * Checks if a credential exists in the keystore.
     * @param credentialId the credential ID to check
     * @return true if the credential exists, false otherwise
     */
    public boolean hasCredential(ByteArray credentialId) {
        try {
            String alias = credentialId.getBase64Url();
            return keyStore.containsAlias(alias) && metadataMap.containsKey(alias);
        } catch (KeyStoreException e) {
            return false;
        }
    }
    
    /**
     * Retrieves the public key for a given credential ID.
     * @param credentialId the credential ID
     * @return the PublicKey, or null if not found
     */
    public PublicKey getPublicKey(ByteArray credentialId) throws KeyStoreException {
        String alias = credentialId.getBase64Url();
        Certificate cert = keyStore.getCertificate(alias);
        return (cert != null) ? cert.getPublicKey() : null;
    }

    /**
     * Retrieves the user handle for a credential.
     * @param credentialId the credential ID
     * @return the user handle as ByteArray, or null if not found
     */
    public ByteArray getUserHandleForCredential(ByteArray credentialId) {
        String alias = credentialId.getBase64Url();
        CredentialMetadata meta = metadataMap.get(alias);
        if (meta != null && meta.user != null && meta.user.get("id") != null) {
            String userIdBase64 = meta.user.get("id").toString();
            return new ByteArray(java.util.Base64.getUrlDecoder().decode(userIdBase64));
        }
        return null;
    }

    /**
     * Gets the current signature counter for a credential.
     * @param credentialId the credential ID
     * @return the current signCount
     */
    public long getSignCount(ByteArray credentialId) {
        String alias = credentialId.getBase64Url();
        CredentialMetadata meta = metadataMap.get(alias);
        if (meta != null && meta.user != null && meta.user.get("signCount") != null) {
            try {
                return Long.parseLong(meta.user.get("signCount").toString());
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    /**
     * Increments and saves the signature counter for a credential.
     * @param credentialId the credential ID
     * @return the new signCount
     */
    public long incrementAndSaveSignCount(ByteArray credentialId) {
        String alias = credentialId.getBase64Url();
        CredentialMetadata meta = metadataMap.get(alias);
        long currentCount = getSignCount(credentialId);
        long newCount = currentCount + 1;
        if (meta != null) {
            if (meta.user == null) meta.user = new HashMap<>();
            meta.user.put("signCount", newCount);
            try {
                saveMetadata();
            } catch (IOException e) {
                System.err.println("Warning: Could not save metadata: " + e.getMessage());
            }
        }
        return newCount;
    }

    /**
     * Generates a random credential ID (16 bytes, UUID-based).
     * @return the credential ID as ByteArray
     */
    public static ByteArray generateRandomCredentialId() {
        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return new ByteArray(bb.array());
    }
}
