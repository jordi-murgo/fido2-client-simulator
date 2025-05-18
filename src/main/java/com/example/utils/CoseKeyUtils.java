package com.example.utils;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utility for encoding Java PublicKey to COSE_Key structure as ByteArray.
 * Supports ES256 (EC P-256) and RS256 (RSA 2048).
 */
public class CoseKeyUtils {
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
        return CborUtils.encodeMap(coseKey);
    }

    private static ByteArray encodeRsaToCose(RSAPublicKey rsaPublicKey) {
        // COSE_Key for RSA:
        // { 1: 3, 3: -257, -1: n, -2: e }
        Map<Integer, Object> coseKey = new LinkedHashMap<>();
        coseKey.put(1, 3); // kty: RSA
        coseKey.put(3, -257); // alg: RS256
        coseKey.put(-1, unsignedBytes(rsaPublicKey.getModulus()));
        coseKey.put(-2, unsignedBytes(rsaPublicKey.getPublicExponent()));
        return CborUtils.encodeMap(coseKey);
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

    /**
     * Converts a COSE-encoded public key to DER format.
     * @param coseKey The COSE-encoded public key as a map
     * @return The DER-encoded public key
     * @throws NoSuchAlgorithmException If the key algorithm is not supported
     * @throws InvalidKeySpecException If the key specification is invalid
     * @throws IOException If there is an error encoding the key
     */
    public static byte[] coseToDer(Map<Object, Object> coseKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        int kty = ((Number) coseKey.get(1)).intValue(); // Key type
        
        if (kty == 2) { // EC2 key type
            return coseEcToDer(coseKey);
        } else if (kty == 3) { // RSA key type
            return coseRsaToDer(coseKey);
        } else {
            throw new UnsupportedOperationException("Unsupported key type: " + kty);
        }
    }
    
    private static byte[] coseEcToDer(Map<Object, Object> coseKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // Get curve and coordinates
        int crv = ((Number) coseKey.get(-1)).intValue();
        byte[] x = (byte[]) coseKey.get(-2);
        byte[] y = (byte[]) coseKey.get(-3);
        
        // Convert coordinates to BigIntegers
        BigInteger xBi = new BigInteger(1, x);
        BigInteger yBi = new BigInteger(1, y);
        
        // Create EC public key spec
        String curveName;
        switch (crv) {
            case 1: curveName = "secp256r1"; break;
            default: throw new UnsupportedOperationException("Unsupported curve: " + crv);
        }
        
        // Get the curve parameters
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        AlgorithmParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        try {
            kpg.initialize(ecSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException("Invalid EC parameter spec: " + curveName, e);
        }
        
        // Create the public key
        ECPoint ecPoint = new ECPoint(xBi, yBi);
        ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, ((ECPublicKey)kpg.generateKeyPair().getPublic()).getParams());
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(ecKeySpec);
        
        // Return DER-encoded key
        return publicKey.getEncoded();
    }
    
    private static byte[] coseRsaToDer(Map<Object, Object> coseKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Get RSA parameters
        byte[] n = (byte[]) coseKey.get(-1); // RSA modulus n
        byte[] e = (byte[]) coseKey.get(-2); // RSA public exponent e
        
        // Convert to BigIntegers
        BigInteger modulus = new BigInteger(1, n);
        BigInteger publicExponent = new BigInteger(1, e);
        
        // Create RSA public key spec
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        
        // Generate the public key
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        
        // Return DER-encoded key
        return publicKey.getEncoded();
    }
    
    /**
     * Converts a COSE-encoded public key to a Java PublicKey object.
     * @param coseKey The COSE-encoded public key as a map
     * @return A PublicKey object
     * @throws NoSuchAlgorithmException If the key algorithm is not supported
     * @throws InvalidKeySpecException If the key specification is invalid
     */
    public static PublicKey coseToPublicKey(Map<Object, Object> coseKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            byte[] der = coseToDer(coseKey);
            int kty = ((Number) coseKey.get("1")).intValue();
            
            if (kty == 2) { // EC
                return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
            } else if (kty == 3) { // RSA
                return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
            } else {
                throw new UnsupportedOperationException("Unsupported key type: " + kty);
            }
        } catch (IOException e) {
            throw new InvalidKeySpecException("Failed to convert COSE to PublicKey: " + e.getMessage(), e);
        }
    }
}
