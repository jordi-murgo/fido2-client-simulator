package com.example.handlers;

import com.example.utils.EncodingUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.data.ByteArray;

import lombok.extern.slf4j.Slf4j;

/**
 * Utility for formatting binary fields in FIDO2/WebAuthn responses to support multiple output styles.
 * Supports: base64url, base64, bytes (Int8 array)
 *
 * Usage example:
 *   ResponseFormatter formatter = new ResponseFormatter("chrome", jsonMapper);
 *   credentialNode.set("id", formatter.formatBinary(credentialId.getBytes(), "id"));
 */
@Slf4j
public class ResponseFormatter {
    public enum Format {
        BASE64URL, // base64url (Default JSON.stringify of WebAuthn PublicKeyCredential)
        BASE64,    // base64 (not url-safe)
        BYTES,     // Int8 array
    }

    private final Format format;
    private final ObjectMapper jsonMapper;

    /**
     * Constructs a ResponseFormatter.
     * @param formatName Output format: base64url, base64, bytes
     * @param jsonMapper Jackson ObjectMapper for array conversion
     */
    public ResponseFormatter(String formatName, ObjectMapper jsonMapper) {
        this.format = parseFormat(formatName);
        this.jsonMapper = jsonMapper;
    }

    /**
     * Converts a format name string to a Format enum value.
     *
     * Supports format names: base64url, base64, bytes
     * @param name the format name string
     * @return the corresponding Format enum value
     */
    private static Format parseFormat(String name) {
        if (name == null) return Format.BASE64URL;
        switch (name.toLowerCase()) {
            case "base64": return Format.BASE64;
            case "bytes": return Format.BYTES;
            case "base64url":
            default: return Format.BASE64URL;
        }
    }

    /**
     * Formats a binary field according to the selected output style.
     * @param bytes The binary data
     * @param fieldName The logical field name (id, rawId, clientDataJSON, etc.)
     * @return JsonNode representing the field in the chosen format
     */
    public JsonNode formatBinary(byte[] bytes, String fieldName) {
        log.info("formatBinary: fieldName={}, format={}, bytes.length={}", fieldName, format, bytes.length);
        switch (format) {
            case BYTES:
                return jsonMapper.valueToTree(bytes);
            case BASE64:
                return jsonMapper.valueToTree(EncodingUtils.base64Encode(bytes));
            default:
                return jsonMapper.valueToTree(EncodingUtils.base64UrlEncode(bytes));
        }
    }

    /**
     * Formats a ByteArray according to the selected output style.
     * @param byteArray The ByteArray object
     * @param fieldName The logical field name (id, rawId, clientDataJSON, etc.)
     * @return JsonNode representing the field in the chosen format
     */
    public JsonNode formatBinary(ByteArray byteArray, String fieldName) {
        return formatBinary(byteArray.getBytes(), fieldName);
    }

    /**
     * Returns the current format.
     */
    public Format getFormat() {
        return format;
    }
}
