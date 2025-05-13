package com.example.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for cryptographic and encoding operations used in FIDO2 simulation.
 */
public class EncodingUtils {

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
    


}
