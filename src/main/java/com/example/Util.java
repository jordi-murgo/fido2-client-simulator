package com.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for cryptographic and encoding operations used in FIDO2 simulation.
 */
public class Util {

    /**
     * Computes the SHA-256 hash of the given byte array.
     * @param input the input bytes
     * @return the SHA-256 hash
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Computes the SHA-256 hash of the given string (UTF-8 encoded).
     * @param input the input string
     * @return the SHA-256 hash
     */
    public static byte[] sha256(String input) {
        return sha256(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encodes the given byte array as Base64URL (no padding).
     * @param data the input bytes
     * @return the Base64URL-encoded string
     */
    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Decodes a Base64URL-encoded string to bytes.
     * @param data the Base64URL string
     * @return the decoded bytes
     */
    public static byte[] base64UrlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    /**
     * Converts a hexadecimal string to a byte array.
     * @param hex the hex string
     * @return the byte array
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
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
