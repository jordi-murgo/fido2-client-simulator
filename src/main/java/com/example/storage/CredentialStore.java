package com.example.storage;

import com.example.utils.EncodingUtils;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Interface for credential storage and retrieval operations.
 * 
 * This interface defines the contract for FIDO2 credential storage and retrieval operations.
 * It follows the Repository pattern and enables dependency inversion according to the SOLID
 * DIP principle, facilitating unit testing and multiple implementations.
 * 
 * @author Jordi Murgo
 * @since 1.0
 */
public interface CredentialStore {
    /**
     * Retrieves the public key for a given credential ID.
     * @param credentialId The credential ID
     * @return Optional containing the public key, or empty if not found
     * @throws KeyStoreException if there is a keystore error
     */
    Optional<PublicKey> getPublicKey(ByteArray credentialId) throws KeyStoreException;

    /**
     * Retrieves the private key for a given credential ID.
     * @param credentialId The credential ID
     * @return Optional containing the private key, or empty if not found
     * @throws KeyStoreException if there is a keystore error
     * @throws UnrecoverableKeyException if the key cannot be recovered
     * @throws NoSuchAlgorithmException if the algorithm for the key cannot be found
     */
    Optional<PrivateKey> getPrivateKey(ByteArray credentialId) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException;
    
    /**
     * Checks if a credential exists.
     * @param credentialId The credential ID to check
     * @return true if the credential exists, false otherwise
     */
    boolean hasCredential(ByteArray credentialId);
    
    /**
     * Gets a list of credential IDs for a relying party ID.
     * @param rpId The relying party ID
     * @return A list of credential IDs
     */
    List<ByteArray> getCredentialIdsForRpId(String rpId);
    
    /**
     * Generates and stores a key pair for a credential.
     * @param credentialId The credential ID
     * @param userHandle The user handle
     * @param alg The COSE algorithm identifier
     * @return The generated key pair
     * @throws Exception if an error occurs during key generation or storage
     */
    KeyPair generateAndStoreKeyPair(ByteArray credentialId, ByteArray userHandle, COSEAlgorithmIdentifier alg) throws Exception;
    
    /**
     * Gets the current signature counter for a credential.
     * @param credentialId The credential ID
     * @return The current signature counter
     */
    long getSignCount(ByteArray credentialId);
    
    /**
     * Increments and saves the signature counter for a credential.
     * @param credentialId The credential ID
     * @return The new signature counter value
     */
    long incrementAndSaveSignCount(ByteArray credentialId);
    
    /**
     * Gets the user handle for a credential.
     * @param credentialId The credential ID
     * @return Optional containing the user handle, or empty if not found
     */
    Optional<ByteArray> getUserHandleForCredential(ByteArray credentialId);
    
    /**
     * Saves metadata to persistent storage.
     * @throws IOException if an error occurs during saving
     */
    void saveMetadata() throws IOException;
    
    /**
     * Returns the metadata map with all credential metadata
     * 
     * @return Map containing credential metadata indexed by credential ID
     */
    Map<String, CredentialMetadata> getMetadataMap();
    
    /**
     * Añade o actualiza metadatos de una credencial en el almacén
     * 
     * @param credentialId El ID de la credencial
     * @param metadata Los metadatos a almacenar
     */
    void addCredentialMetadata(String credentialId, CredentialMetadata metadata);
    
    /**
     * Retrieves credentials that meet a specific criterion.
     * 
     * This method uses functional programming to filter and transform
     * stored credentials according to the provided predicate. It implements
     * the Specification pattern in its functional form using Predicate.
     * 
     * @param filter Functional specification that defines the filtering criteria
     * @return Immutable list of credential identifiers that meet the criteria
     * @see java.util.function.Predicate
     * @since 1.0
     */
    default List<ByteArray> getCredentialsByPredicate(Predicate<CredentialMetadata> filter) {
        Objects.requireNonNull(filter, "El predicado de filtrado no puede ser nulo");
        
        return getMetadataMap().values().stream()
                .filter(filter)
                .map(this::extractCredentialId)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toUnmodifiableList());
    }
    
    /**
     * Extracts the credential identifier from the metadata.
     * Helper method that encapsulates the decoding logic and error handling.
     * 
     * @param meta Credential metadata
     * @return Optional containing the ByteArray ID if decoding was successful
     */
    default Optional<ByteArray> extractCredentialId(CredentialMetadata meta) {
        try {
            return Optional.ofNullable(meta.credentialId)
                   .map(id -> new ByteArray(EncodingUtils.base64UrlDecode(id)));
        } catch (Exception e) {
            // Logging silencioso de errores para no interrumpir el flujo de procesamiento
            return Optional.empty();
        }
    }
}
