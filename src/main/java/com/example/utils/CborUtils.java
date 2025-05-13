package com.example.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.webauthn.data.ByteArray;

/**
 * Utility for encoding and decoding CBOR data for FIDO2/WebAuthn operations.
 */
public final class CborUtils {
    private static final Logger LOGGER = Logger.getLogger(CborUtils.class.getName());
    
    private CborUtils() {
        // Private constructor to prevent instantiation of utility class
    }

    /**
     * Encode a Map with String or Integer keys to CBOR ByteArray.
     * Only String and Integer keys are supported for WebAuthn/COSE/attestation objects.
     * 
     * @param map The map to encode
     * @return ByteArray containing CBOR encoding
     * @throws IllegalArgumentException if the map contains unsupported key types
     */
    public static ByteArray encodeMap(Map<?, Object> map) {
        if (map == null) {
            throw new IllegalArgumentException("Map cannot be null");
        }
        
        CBORObject cborMap = CBORObject.NewMap();
        
        for (Map.Entry<?, Object> entry : map.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();
            
            CBORObject cborKey;
            if (key instanceof Integer) {
                cborKey = CBORObject.FromInt32((Integer) key);
            } else if (key instanceof String) {
                cborKey = CBORObject.FromObject((String) key);
            } else {
                throw new IllegalArgumentException("Unsupported key type: " + 
                    (key != null ? key.getClass().getName() : "null"));
            }
            
            try {
                CBORObject cborValue = CBORObject.FromObject(value);
                cborMap.Add(cborKey, cborValue);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Error encoding value of type " + 
                    (value != null ? value.getClass().getName() : "null"), e);
                throw new IllegalArgumentException("Failed to encode value: " + e.getMessage(), e);
            }
        }
        
        return new ByteArray(cborMap.EncodeToBytes());
    }
    
    /**
     * Decode a CBOR ByteArray to a Java Map.
     * 
     * @param bytes The CBOR-encoded ByteArray
     * @return A Map representing the decoded CBOR data
     * @throws IllegalArgumentException if the bytes cannot be decoded
     */
    public static Map<Object, Object> decodeToMap(ByteArray bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("Bytes cannot be null");
        }
        
        try {
            CBORObject cbor = CBORObject.DecodeFromBytes(bytes.getBytes());
            if (cbor.getType() != CBORType.Map) {
                throw new IllegalArgumentException("Decoded CBOR is not a map");
            }
            
            // Convert CBORObject map to Java Map
            Map<Object, Object> result = new HashMap<>();
            for (CBORObject key : cbor.getKeys()) {
                Object keyObj;
                if (key.isNumber()) {
                    keyObj = key.AsNumber().ToInt32IfExact();
                } else if (key.getType() == CBORType.TextString) {
                    keyObj = key.AsString();
                } else {
                    keyObj = key;
                }
                
                CBORObject value = cbor.get(key);
                Object valueObj;
                
                if (value.getType() == CBORType.ByteString) {
                    valueObj = value.GetByteString();
                } else if (value.getType() == CBORType.TextString) {
                    valueObj = value.AsString();
                } else if (value.isNumber()) {
                    valueObj = value.AsNumber().ToInt32IfExact();
                } else if (value.getType() == CBORType.Boolean && value.AsBoolean()) {
                    valueObj = Boolean.TRUE;
                } else if (value.getType() == CBORType.Boolean && !value.AsBoolean()) {
                    valueObj = Boolean.FALSE;
                } else if (value.isNull()) {
                    valueObj = null;
                } else {
                    valueObj = value;
                }
                
                result.put(keyObj, valueObj);
            }
            
            return result;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to decode CBOR", e);
            throw new IllegalArgumentException("Failed to decode CBOR: " + e.getMessage(), e);
        }
    }
}
