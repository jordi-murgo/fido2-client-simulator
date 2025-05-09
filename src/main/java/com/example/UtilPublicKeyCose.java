package com.example;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utility for encoding Java PublicKey to COSE_Key structure as ByteArray.
 * Supports ES256 (EC P-256) and RS256 (RSA 2048).
 */
public class UtilPublicKeyCose {
    /**
     * Encode a Java PublicKey to COSE_Key format as ByteArray.
     * Only supports ES256 (EC) and RS256 (RSA).
     * @param publicKey The public key
     * @param alg The COSE algorithm identifier
     * @return ByteArray containing the CBOR-encoded COSE_Key
     */
    public static ByteArray encodeToCose(PublicKey publicKey, COSEAlgorithmIdentifier alg) {
        if (publicKey instanceof ECPublicKey && alg == COSEAlgorithmIdentifier.ES256) {
            return encodeEcToCose((ECPublicKey) publicKey);
        } else if (publicKey instanceof RSAPublicKey && alg == COSEAlgorithmIdentifier.RS256) {
            return encodeRsaToCose((RSAPublicKey) publicKey);
        } else {
            throw new IllegalArgumentException("Unsupported key type/algorithm for COSE encoding: " + publicKey.getAlgorithm() + ", " + alg);
        }
    }

    private static ByteArray encodeEcToCose(ECPublicKey ecPublicKey) {
        // COSE_Key for EC2:
        // { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
        Map<Integer, Object> coseKey = new LinkedHashMap<>();
        coseKey.put(1, 2); // kty: EC2
        coseKey.put(3, -7); // alg: ES256
        coseKey.put(-1, 1); // crv: P-256
        coseKey.put(-2, unsignedCoordinate(ecPublicKey.getW().getAffineX(), 32));
        coseKey.put(-3, unsignedCoordinate(ecPublicKey.getW().getAffineY(), 32));
        return CborUtil.encodeMap(coseKey);
    }

    private static ByteArray encodeRsaToCose(RSAPublicKey rsaPublicKey) {
        // COSE_Key for RSA:
        // { 1: 3, 3: -257, -1: n, -2: e }
        Map<Integer, Object> coseKey = new LinkedHashMap<>();
        coseKey.put(1, 3); // kty: RSA
        coseKey.put(3, -257); // alg: RS256
        coseKey.put(-1, unsignedBytes(rsaPublicKey.getModulus()));
        coseKey.put(-2, unsignedBytes(rsaPublicKey.getPublicExponent()));
        return CborUtil.encodeMap(coseKey);
    }

    private static byte[] unsignedCoordinate(BigInteger coord, int length) {
        byte[] bytes = unsignedBytes(coord);
        if (bytes.length == length) return bytes;
        byte[] out = new byte[length];
        System.arraycopy(bytes, 0, out, length - bytes.length, bytes.length);
        return out;
    }

    private static byte[] unsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }
}
