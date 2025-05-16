package com.example.utils;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Utility class for decoding WebAuthn authenticator data.
 * The authenticator data structure is defined in the WebAuthn specification.
 */
public class AuthDataUtils {

    /**
     * Decodes the authenticator data and returns a human-readable representation.
     * @param authData The raw authenticator data bytes
     * @return A string containing the decoded components
     */
    public static String decodeAuthData(byte[] authData) {
        if (authData == null || authData.length < 37) {
            return "Invalid authData (too short)";
        }

        StringBuilder sb = new StringBuilder();
        
        // Extract rpIdHash (first 32 bytes)
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        
        // Extract flags (1 byte)
        byte flags = authData[32];
        boolean userPresent = (flags & 0x01) != 0;
        boolean userVerified = (flags & 0x04) != 0;
        boolean attestedCredentialData = (flags & 0x40) != 0;
        boolean extensionDataIncluded = (flags & 0x80) != 0;
        
        // Extract signCount (4 bytes)
        int signCount = ByteBuffer.wrap(authData, 33, 4).getInt();
        
        sb.append("rpIdHash: ").append(bytesToHex(rpIdHash)).append("\n");
        sb.append("flags: 0x").append(String.format("%02X", flags)).append(" (");
        sb.append("UP=").append(userPresent ? "1" : "0").append(", ");
        sb.append("UV=").append(userVerified ? "1" : "0").append(", ");
        sb.append("AT=").append(attestedCredentialData ? "1" : "0").append(", ");
        sb.append("ED=").append(extensionDataIncluded ? "1" : "0").append(")\n");
        sb.append("signCount: ").append(signCount).append("\n");
        
        // If attested credential data is present, decode it
        if (attestedCredentialData && authData.length >= 55) {
            // Extract AAGUID (16 bytes)
            byte[] aaguid = new byte[16];
            System.arraycopy(authData, 37, aaguid, 0, 16);
            
            // Format AAGUID as UUID
            UUID aaguidUuid = getUuidFromBytes(aaguid);
            
            // Extract credentialIdLength (2 bytes)
            int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
            
            sb.append("aaguid: ").append(aaguidUuid).append("\n");
            sb.append("credentialIdLength: ").append(credentialIdLength).append("\n");
            
            // Extract credentialId (variable length)
            if (authData.length >= 55 + credentialIdLength) {
                byte[] credentialId = new byte[credentialIdLength];
                System.arraycopy(authData, 55, credentialId, 0, credentialIdLength);
                sb.append("credentialId: ").append(EncodingUtils.base64UrlEncode(credentialId)).append("\n");
                
                // The rest is CBOR-encoded public key
                int publicKeyOffset = 55 + credentialIdLength;
                if (authData.length > publicKeyOffset) {
                    byte[] publicKeyCbor = new byte[authData.length - publicKeyOffset];
                    System.arraycopy(authData, publicKeyOffset, publicKeyCbor, 0, publicKeyCbor.length);
                    sb.append("credentialPublicKey: ").append(bytesToHex(publicKeyCbor, 16)).append("...");
                }
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Converts a byte array to a UUID.
     */
    private static UUID getUuidFromBytes(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long high = bb.getLong();
        long low = bb.getLong();
        return new UUID(high, low);
    }
    
    /**
     * Converts a byte array to a hexadecimal string.
     */
    private static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, bytes.length);
    }
    
    /**
     * Converts a byte array to a hexadecimal string with a limit on the number of bytes.
     */
    private static String bytesToHex(byte[] bytes, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(bytes.length, maxBytes);
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        if (limit < bytes.length) {
            sb.append("...");
        }
        return sb.toString();
    }
}
