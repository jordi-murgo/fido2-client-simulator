package com.example.storage;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.Optional;

import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.example.config.ConfigurationManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import lombok.extern.slf4j.Slf4j;

/**
 * Manages the Java KeyStore (JKS) for FIDO2 credential key pairs and a separate properties file for credential metadata.
 * Handles key pair generation, storage, retrieval, and metadata management (signCount, userHandle).
 */
/**
 * Implementation of {@link CredentialStore} based on Java KeyStore.
 * 
 * This class provides a robust implementation of the credential store
 * using Java's standard KeyStore mechanism as a backend. It manages the
 * complete lifecycle of FIDO2 credentials, including key generation,
 * storage, retrieval, and associated metadata.
 * 
 * @author Jordi Murgo
 * @since 1.0
 */
@Slf4j
@Getter
public class KeyStoreManager implements CredentialStore {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private final ConfigurationManager config = ConfigurationManager.getInstance();
    private final String keystorePath;
    private final String metadataPath;
    private final String keystorePassword;
    
    // Variables para almacenar las fechas de última actualización
    private long lastKeystoreUpdate = 0;
    private long lastMetadataUpdate = 0;
    
    /**
     * Returns the metadata map with all credential metadata
     * 
     * @return Map containing credential metadata indexed by credential ID
     */
    @Override
    public Map<String, CredentialMetadata> getMetadataMap() {
        return Collections.unmodifiableMap(metadataMap);
    }
    
    /**
     * Añade o actualiza los metadatos de una credencial
     * 
     * @param credentialId El ID de la credencial
     * @param metadata Los metadatos a almacenar
     */
    @Override
    public void addCredentialMetadata(String credentialId, CredentialMetadata metadata) {
        // Modificar directamente el mapa interno, no el que se devuelve por getMetadataMap()
        metadataMap.put(credentialId, metadata);
    }
    
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

    public KeyStoreManager() throws Exception {
        // Initialize configuration properties
        keystorePath = config.getKeystorePath();
        metadataPath = config.getMetadataPath();
        keystorePassword = config.getKeystorePassword();
        
        log.debug("Initializing KeyStoreManager with keystore path: {}, metadata path: {}", 
                  new Object[]{keystorePath, metadataPath});
        
        // Initialize the KeyStore
        keyStore = KeyStore.getInstance("PKCS12", PROVIDER);
        
        // Check if the keystore file exists, if not create a new one
        File keystoreFile = new File(keystorePath);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, keystorePassword.toCharArray());
                log.debug("Loaded existing keystore from: {}", keystorePath);
            }
        } else {
            // Create an empty keystore
            keyStore.load(null, keystorePassword.toCharArray());
            log.debug("Created new empty keystore");
        }
        try {
            loadMetadata();
        } catch (Exception e) {
            log.error("Error loading metadata", e);
            metadataMap = new HashMap<>();
        }
    }

    @Override
    public void saveMetadata() throws IOException {
        // Create file object for metadata path
        File metadataFile = new File(metadataPath);
        
        // If the file has a parent directory, ensure it exists
        if (metadataFile.getParentFile() != null) {
            metadataFile.getParentFile().mkdirs();
        }
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT); // Pretty print
        mapper.writeValue(metadataFile, metadataMap);
        log.debug("Metadata saved to: {}", metadataPath);
    }

    /**
     * Loads credential metadata from the configured metadata file
     */
    public void loadMetadata() {
        // Load metadata if it exists
        metadataMap = new HashMap<>();
        File metadataFile = new File(metadataPath);
        if (metadataFile.exists()) {
            try (FileInputStream fis = new FileInputStream(metadataFile)) {
                // If the metadataMap is empty, we need to create a new map
                HashMap<String, CredentialMetadata> loadedMap = jsonMapper.readValue(fis, 
                        new TypeReference<HashMap<String, CredentialMetadata>>() {});
                if (loadedMap != null) {
                    metadataMap.clear();
                    metadataMap.putAll(loadedMap);
                }
                // Actualizar la fecha de última modificación desde el archivo
                lastMetadataUpdate = metadataFile.lastModified();
                log.debug("Loaded metadata from: {}, found {} credentials",
                        new Object[]{metadataPath, metadataMap.size()});
            } catch (IOException e) {
                log.error("Failed to load metadata from: " + metadataPath, e);
                // Continue with empty metadata if file is corrupted
                metadataMap.clear();
            }
        } else {
            log.debug("No metadata file found, will create: {}", metadataPath);
        }
    }

    /**
     * Returns a list of credential IDs (ByteArray) associated with the given rpId.
     * @param rpId the relying party ID
     * @return a list of credential IDs (ByteArray)
     */
    @Override
    public List<ByteArray> getCredentialIdsForRpId(String rpId) {
        // Utilizamos el método default de la interfaz que implementa un enfoque funcional
        return getCredentialsByPredicate(meta -> 
            meta.rp != null && rpId.equals(meta.rp.get("id")));
    }

    private void saveKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        // Create file object for keystore path
        File keystoreFile = new File(keystorePath);
        
        // If the file has a parent directory, ensure it exists
        if (keystoreFile.getParentFile() != null) {
            keystoreFile.getParentFile().mkdirs();
        }
        
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
            lastKeystoreUpdate = System.currentTimeMillis();
            log.debug("Keystore saved to: {}", keystorePath);
        }
    }

    /**
     * Generates a key pair for a credential and stores it in the keystore.
     * 
     * This method implements the Factory Method pattern for generating cryptographic
     * key pairs, supporting different COSE algorithms. Additionally, it manages the complete
     * persistence cycle for both the keys and their associated metadata.
     *
     * @param credentialId Unique identifier for the FIDO2 credential
     * @param userHandle User identifier associated with the credential
     * @param alg COSE algorithm identifier to use
     * @return Generated key pair (public/private)
     * @throws Exception If an error occurs during generation or storage
     */
    @Override
    public KeyPair generateAndStoreKeyPair(ByteArray credentialId, ByteArray userHandle, COSEAlgorithmIdentifier alg) throws Exception {
        Objects.requireNonNull(credentialId, "Credential identifier cannot be null");
        Objects.requireNonNull(userHandle, "User identifier cannot be null");
        Objects.requireNonNull(alg, "Algorithm cannot be null");
        
        final String alias = credentialId.getBase64Url();
        log.debug("Generating key pair for credential: " + alias + " with algorithm: " + alg);
        
        // Key pair generation using Factory Method pattern
        final KeyPair keyPair = createKeyPairForAlgorithm(alg);
        
        try {
            // Determine the appropriate signature algorithm based on the key type
            String sigAlgName = keyPair.getPrivate() instanceof java.security.interfaces.RSAPrivateKey 
                ? "SHA256withRSA" 
                : "SHA256withECDSA";
                
            // Store the key pair in the keystore with a self-signed certificate
            final Certificate[] certChain = { createSelfSignedCertificate(keyPair, sigAlgName, userHandle) };
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keystorePassword.toCharArray(), certChain);
            saveKeyStore();
            
            // Create and store metadata
            CredentialMetadata meta = new CredentialMetadata();
            meta.credentialId = alias;
            meta.createdAt = System.currentTimeMillis();
            
            // Store user identifier in metadata
            Map<String, Object> user = new HashMap<>();
            user.put("id", userHandle.getBase64Url());
            meta.user = user;
            
            // Store algorithm information
            meta.rp = new HashMap<>(); // Inicializar mapa de RP si es necesario
            
            metadataMap.put(alias, meta);
            saveMetadata();
            log.debug("Key pair successfully generated and stored for: " + alias);
            return keyPair;
        } catch (Exception e) {
            log.error("Error storing key pair", e);
            throw new KeyStoreException("Error storing key pair: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a key pair for the specified algorithm.
     * Implementation of the Factory Method pattern for key generation.
     *
     * @param alg COSE algorithm for which to generate keys
     * @return Generated key pair
     * @throws NoSuchAlgorithmException If the algorithm is not supported
     * @throws NoSuchProviderException If the cryptographic provider is not available
     * @throws InvalidAlgorithmParameterException If the algorithm parameters are invalid
     */
    private KeyPair createKeyPairForAlgorithm(COSEAlgorithmIdentifier alg) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        
        switch (alg) {
            case ES256: // EC key pair (P-256)
                KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", PROVIDER);
                ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
                return ecKeyGen.generateKeyPair();
                
            case RS256: // RSA key pair (2048-bit)
                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", PROVIDER);
                rsaKeyGen.initialize(2048);
                return rsaKeyGen.generateKeyPair();
                
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }
    }
    
    /**
     * Creates a self-signed certificate for the specified key pair.
     * 
     * This method uses BouncyCastle to generate a simple X.509 certificate
     * that is used to store the public key in the KeyStore.
     *
     * @param keyPair Key pair for which to generate the certificate
     * @param sigAlgName Signature algorithm name
     * @param userHandle User identifier as part of the DN
     * @return Self-signed certificate
     * @throws Exception If an error occurs during certificate generation
     */
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
     * @throws KeyStoreException if there is a keystore error
     * @throws UnrecoverableKeyException if the key cannot be recovered
     */
    @Override
    public Optional<PrivateKey> getPrivateKey(ByteArray credentialId) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        String alias = credentialId.getBase64Url();
        Key key = keyStore.getKey(alias, keystorePassword.toCharArray());
        return Optional.ofNullable(key)
                .filter(k -> k instanceof PrivateKey)
                .map(k -> (PrivateKey) k);
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
    /**
     * Retrieves the public key associated with a credential identifier.
     * 
     * This method implements a secure lookup of the public key in the Java KeyStore,
     * using the credential identifier as an alias. It employs the Adapter design pattern
     * to transform the KeyStore exception model into a more functional model based on Optional.
     *
     * @param credentialId The FIDO2 credential identifier
     * @return Optional containing the public key if it exists, or empty if not found
     * @throws KeyStoreException If an error occurs in the underlying key store
     * @see java.security.KeyStore#getCertificate(String)
     */
    @Override
    public Optional<PublicKey> getPublicKey(ByteArray credentialId) throws KeyStoreException {
        assert credentialId != null : "Credential identifier cannot be null";
        
        final String alias = credentialId.getBase64Url();
        final Certificate cert = keyStore.getCertificate(alias);
        
        return Optional.ofNullable(cert)
                .map(Certificate::getPublicKey)
                .map(key -> {
                    log.debug("Public key retrieved for credential: " + alias);
                    return key;
                });
    }

    /**
     * Retrieves the user handle for a credential.
     * @param credentialId the credential ID
     * @return the user handle as ByteArray, or null if not found
     */
    @Override
    public Optional<ByteArray> getUserHandleForCredential(ByteArray credentialId) {
        String alias = credentialId.getBase64Url();
        return Optional.ofNullable(metadataMap.get(alias))
                .filter(meta -> meta.user != null && meta.user.get("id") != null)
                .map(meta -> {
                    String userIdBase64 = meta.user.get("id").toString();
                    return new ByteArray(java.util.Base64.getUrlDecoder().decode(userIdBase64));
                });
    }
    
    /**
     * Retrieves user information (name, displayName) for a credential.
     * @param credentialId the credential ID
     * @return a Map containing user information, or null if not found
     */
    public Map<String, String> getUserInfoForCredential(ByteArray credentialId) {
        String alias = credentialId.getBase64Url();
        CredentialMetadata meta = metadataMap.get(alias);
        if (meta != null && meta.user != null) {
            Map<String, String> userInfo = new HashMap<>();
            
            // Extract user name
            if (meta.user.get("name") != null) {
                userInfo.put("name", meta.user.get("name").toString());
            } else {
                userInfo.put("name", "<unknown>");
            }
            
            // Extract display name
            if (meta.user.get("displayName") != null) {
                userInfo.put("displayName", meta.user.get("displayName").toString());
            } else {
                userInfo.put("displayName", "<unknown>");
            }
            
            return userInfo;
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
     * Generates a random credential identifier.
     * 
     * This method creates a unique 16-byte identifier based on UUID,
     * following FIDO2 recommendations for generating credential identifiers
     * with high entropy. It uses a functional and fluent approach for
     * data transformation.
     * 
     * The current implementation uses UUID v4 (completely random) as a base,
     * which provides 122 bits of entropy, sufficient to avoid collisions
     * in production environments.
     *
     * @return Credential identifier as ByteArray
     * @see java.util.UUID#randomUUID()
     */
    public static ByteArray generateRandomCredentialId() {
        // Generate a UUID v4 (completely random)
        final UUID uuid = UUID.randomUUID();
        log.debug("Generating credential ID based on UUID: ", uuid);
        
        // Transform to ByteArray using ByteBuffer (fluent approach)
        return new ByteArray(
            ByteBuffer.wrap(new byte[16])
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array()
        );
    }
}
