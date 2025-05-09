package com.example;

import com.yubico.webauthn.data.ByteArray;
import com.upokecenter.cbor.CBORObject;

import java.io.IOException;
import java.util.Map;

/**
 * Utility for encoding Java Maps to CBOR ByteArray for COSE keys.
 */
public class CborUtil {
    /**
     * Encode a Map with String or Integer keys to CBOR ByteArray.
     * Only String and Integer keys are supported for WebAuthn/COSE/attestation objects.
     * This version uses CBORObject to guarantee correct byte string encoding for byte[].
     * @param map The map to encode
     * @return ByteArray containing CBOR encoding
     */
    public static ByteArray encodeMap(Map<?, Object> map) {
        CBORObject cborMap = CBORObject.NewMap();
        for (Map.Entry<?, Object> entry : map.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();
            CBORObject cborKey;
            if (key instanceof Integer) {
                cborKey = CBORObject.FromObject((Integer) key);
            } else if (key instanceof String) {
                cborKey = CBORObject.FromObject((String) key);
            } else {
                throw new IllegalArgumentException("Unsupported key type: " + key.getClass());
            }
            CBORObject cborValue = (value instanceof byte[])
                ? CBORObject.FromObject((byte[]) value)
                : CBORObject.FromObject(value);
            cborMap.set(cborKey, cborValue);
        }
        return new ByteArray(cborMap.EncodeToBytes());
    }
}
