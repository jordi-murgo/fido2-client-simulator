package com.example.utils;

import java.util.Base64;

/**
 * Utility class for cryptographic and encoding operations used in FIDO2
 * simulation.
 */
public class EncodingUtils {

    /**
     * Encodes the given byte array as Base64URL (no padding).
     * 
     * @param data the input bytes
     * @return the Base64URL-encoded string
     */
    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Encodes the given byte array as Base64 (no padding).
     * 
     * @param data the input bytes
     * @return the Base64-encoded string
     */
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Decodes a Base64URL-encoded string to bytes.
     * 
     * @param data the Base64URL string
     * @return the decoded bytes
     */
    public static byte[] base64UrlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    public static byte[] base64UrlDecode(byte[] data) {
        return Base64.getUrlDecoder().decode(data);
    }


    /**
     * Decodes a Base64-encoded string to bytes.
     * 
     * @param data the Base64 string
     * @return the decoded bytes
     */
    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static byte[] base64Decode(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    /**
     * Converts a hexadecimal string to a byte array.
     * 
     * @param hex the hex string
     * @return the byte array
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Tries to decode a string as Base64URL, then Base64, then hex, then raw bytes.
     * 
     * @param data the string to decode
     * @return the decoded bytes
     */
    public static byte[] magicDecode(String data) {
        try {
            return base64UrlDecode(data);
        } catch (Exception e) {
            try {
                return base64Decode(data);
            } catch (Exception e2) {
                return data.getBytes();
            }
        }
    }

    /**
     * Returns the input bytes as-is.
     * 
     * @param data the bytes to return
     * @return the input bytes
     */
    public static byte[] magicDecode(byte[] data) {
        return data;
    }

    /**
     * Attempts to decode a potentially Base64-encoded JSON string. This method will
     * try:
     * 1. URL-safe Base64 decoding
     * 2. Standard Base64 decoding
     * 3. Return the original string if both decode attempts fail
     *
     * This is useful for handling WebAuthn data that might be Base64-encoded when
     * passing
     * between systems or through environments that might interfere with JSON
     * formatting.
     *
     * @param potentiallyEncodedJson A string that may be Base64 encoded JSON
     * @return The decoded JSON string or the original string if not Base64 encoded
     */
    public static String tryDecodeBase64Json(String potentiallyEncodedJson) {
        try {
            // Try to decode the options JSON as a Base64 URL string
            return new String(EncodingUtils.base64UrlDecode(potentiallyEncodedJson));
        } catch (Exception e) {
            try {
                // Try to decode the options JSON as a standard Base64 string
                return new String(EncodingUtils.base64Decode(potentiallyEncodedJson));
            } catch (Exception e2) {
                // If it's not a Base64 string, just return it as is
                return potentiallyEncodedJson;
            }
        }
    }

    public static byte[] tryDecodeBase64(byte[] potentiallyEncodedJson) {
        try {
            // Try to decode the options JSON as a Base64 URL string
            return EncodingUtils.base64UrlDecode(potentiallyEncodedJson);
        } catch (Exception e) {
            try {
                // Try to decode the options JSON as a standard Base64 string
                return EncodingUtils.base64Decode(potentiallyEncodedJson);
            } catch (Exception e2) {
                // If it's not a Base64 string, just return it as is
                return potentiallyEncodedJson;
            }
        }
    }
}
