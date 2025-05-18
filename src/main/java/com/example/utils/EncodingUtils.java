package com.example.utils;

import java.util.Base64;

/**
 * Utility class for cryptographic and encoding operations used in FIDO2 simulation.
 */
public class EncodingUtils {

    /**
     * Encodes the given byte array as Base64URL (no padding).
     * @param data the input bytes
     * @return the Base64URL-encoded string
     */
    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Encodes the given byte array as Base64 (no padding).
     * @param data the input bytes
     * @return the Base64-encoded string
     */
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
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
     * Decodes a Base64-encoded string to bytes.
     * @param data the Base64 string
     * @return the decoded bytes
     */
    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
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
     * Tries to decode a string as Base64URL, then Base64, then hex, then raw bytes.
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
     * @param data the bytes to return
     * @return the input bytes
     */
    public static byte[] magicDecode(byte[] data) {
        return data;
    }
}
