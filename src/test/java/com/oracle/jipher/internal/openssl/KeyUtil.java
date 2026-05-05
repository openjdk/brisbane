/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.oracle.jipher.internal.openssl;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.oracle.jiphertest.testdata.KeyParts;

import static com.oracle.jipher.internal.common.EcUtil.encodePointUncompressed;
import static com.oracle.jipher.internal.common.NamedCurves.lookup;

public class KeyUtil {

    public static EVP_PKEY loadPrivate(KeySpec keySpec, OSSL_LIB_CTX libCtx, OsslArena arena) throws Exception {
        if (keySpec instanceof DSAPrivateKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((DSAPrivateKeySpec) keySpec);
            return newPriv("DSA", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof DHPrivateKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((DHPrivateKeySpec) keySpec);
            return newPriv("DH", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof ECPrivateKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((ECPrivateKeySpec) keySpec);
            return newPriv("EC", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof RSAPrivateCrtKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((RSAPrivateCrtKeySpec) keySpec);
            return newPriv("RSA", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else {
            throw new Exception("Unsupported key specification: " + keySpec.getClass().getName());
        }
    }

    public static EVP_PKEY loadPublic(KeySpec keySpec, OSSL_LIB_CTX libCtx, OsslArena arena) throws Exception {
        if (keySpec instanceof DSAPublicKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((DSAPublicKeySpec) keySpec);
            return newPub("DSA", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof DHPublicKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((DHPublicKeySpec) keySpec);
            return newPub("DH", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof ECPublicKeySpec) {
            ArrayList<OSSL_PARAM> params = newParams((ECPublicKeySpec) keySpec);
            return newPub("EC", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else if (keySpec instanceof RSAPublicKeySpec)  {
            ArrayList<OSSL_PARAM> params = newParams((RSAPublicKeySpec) keySpec);
            return newPub("RSA", libCtx, arena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } else {
            throw new Exception("Unsupported key specification: " + keySpec.getClass().getName());
        }
    }

    public static KeySpec getPrivateKeySpec(String alg, String secParam, KeyParts keyParts) throws Exception {
        if (alg.equals("DSA")) {
            BigInteger x = new BigInteger(1, keyParts.getPrivValue());
            BigInteger p = new BigInteger(1, keyParts.getP());
            BigInteger q = new BigInteger(1, keyParts.getQ());
            BigInteger g = new BigInteger(1, keyParts.getG());

            return new DSAPrivateKeySpec(x, p, q, g);
        } else if (alg.equals("DH")) {
            BigInteger x = new BigInteger(1, keyParts.getPrivValue());
            BigInteger p = new BigInteger(1, keyParts.getP());
            BigInteger g = new BigInteger(1, keyParts.getG());

            return new DHPrivateKeySpec(x, p, g);
        } else if (alg.equals("EC")) {
            BigInteger s = new BigInteger(1, keyParts.getPrivValue());
            ECParameterSpec params = lookup(secParam);

            return new ECPrivateKeySpec(s, params);
        } else if (alg.equals("RSA")) {
            BigInteger modulus = new BigInteger(1, keyParts.getN());
            BigInteger publicExponent =  new BigInteger(1, keyParts.getE());
            BigInteger privateExponent =  new BigInteger(1, keyParts.getD());
            BigInteger primeP = new BigInteger(1, keyParts.getP());
            BigInteger primeQ = new BigInteger(1, keyParts.getQ());
            BigInteger primeExponentP = new BigInteger(1, keyParts.getExpP());
            BigInteger primeExponentQ = new BigInteger(1, keyParts.getExpQ());
            BigInteger crtCoefficient = new BigInteger(1, keyParts.getCrtCoeff());

            return new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ,
                    primeExponentP, primeExponentQ, crtCoefficient);
        } else {
            throw new Exception("Unsupported algorithm: " + alg);
        }
    }

    public static KeySpec getPublicKeySpec(String alg, String secParam, KeyParts keyParts) throws Exception {
        if (alg.equals("DSA")) {
            BigInteger y = new BigInteger(1, keyParts.getPubValue());
            BigInteger p = new BigInteger(1, keyParts.getP());
            BigInteger q = new BigInteger(1, keyParts.getQ());
            BigInteger g = new BigInteger(1, keyParts.getG());

            return new DSAPublicKeySpec(y, p, q, g);
        } else if (alg.equals("DH")) {
            BigInteger y = new BigInteger(1, keyParts.getPubValue());
            BigInteger p = new BigInteger(1, keyParts.getP());
            BigInteger g = new BigInteger(1, keyParts.getG());

            return new DHPublicKeySpec(y, p, g);
        } else if (alg.equals("EC")) {
            BigInteger x = new BigInteger(1, keyParts.getPubX());
            BigInteger y = new BigInteger(1,  keyParts.getPubY());
            ECPoint w = new ECPoint(x, y);
            ECParameterSpec params = lookup(secParam);
            return new ECPublicKeySpec(w, params);
        } else if (alg.equals("RSA")) {
            BigInteger modulus = new BigInteger(1, keyParts.getN());
            BigInteger publicExponent =  new BigInteger(1, keyParts.getE());

            return new RSAPublicKeySpec(modulus, publicExponent);

        } else {
            throw new Exception("Unsupported algorithm: " + alg);
        }
    }

    public static KeySpec getPrivateKeySpec(String alg, byte[] encoding) throws Exception {
        // Use JDK providers to asn1 decode the key encoding into a key spec
        if (alg.equals("DSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SUN");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), DSAPrivateKeySpec.class);
        } else if (alg.equals("DH")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunJCE");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), DHPrivateKeySpec.class);
        } else if (alg.equals("EC")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunEC");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), ECPrivateKeySpec.class);
        } else if (alg.equals("RSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunRsaSign");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), RSAPrivateCrtKeySpec.class);
        } else if (alg.equals("ML-KEM")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunJCE");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), PKCS8EncodedKeySpec.class);
        } else if (alg.equals("ML-DSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SUN");
            return kf.getKeySpec(kf.generatePrivate(new PKCS8EncodedKeySpec(encoding)), PKCS8EncodedKeySpec.class);
        } else {
            throw new Exception("Unsupported algorithm: " + alg);
        }
    }

    public static KeySpec getPublicKeySpec(String alg, byte[] encoding) throws Exception {
        // Use JDK providers to asn1 decode the key encoding into a key spec
        if (alg.equals("DSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SUN");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), DSAPublicKeySpec.class);
        } else if (alg.equals("DH")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunJCE");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), DHPublicKeySpec.class);
        } else if (alg.equals("EC")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunEC");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), ECPublicKeySpec.class);
        } else if (alg.equals("RSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunRsaSign");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), RSAPublicKeySpec.class);
        } else if (alg.equals("ML-KEM")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SunJCE");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), X509EncodedKeySpec.class);
        } else if (alg.equals("ML-DSA")) {
            KeyFactory kf = KeyFactory.getInstance(alg, "SUN");
            return kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(encoding)), X509EncodedKeySpec.class);
        }
        else {
            throw new Exception("Unsupported algorithm: " + alg);
        }
    }

    public static ArrayList<OSSL_PARAM> newParams(DSAPrivateKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, keySpec.getP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_Q, keySpec.getQ()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, keySpec.getG()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PRIV_KEY, keySpec.getX()));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(DHPrivateKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, keySpec.getP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, keySpec.getG()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PRIV_KEY, keySpec.getX()));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(ECPrivateKeySpec keySpec) {
        EcCurve curve = lookup(keySpec.getParams());

        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PRIV_KEY, keySpec.getS()));
        /* Do not attempt to encode the public key */
        params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_EC_INCLUDE_PUBLIC, 0));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(RSAPrivateCrtKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_N, keySpec.getModulus()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_E, keySpec.getPublicExponent()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_D, keySpec.getPrivateExponent()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_FACTOR1, keySpec.getPrimeP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_FACTOR2,  keySpec.getPrimeQ()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT1, keySpec.getPrimeExponentP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT2, keySpec.getPrimeExponentQ()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_COEFFICIENT1, keySpec.getCrtCoefficient()));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(DSAPublicKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, keySpec.getP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_Q, keySpec.getQ()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, keySpec.getG()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PUB_KEY, keySpec.getY()));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(DHPublicKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, keySpec.getP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, keySpec.getG()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PUB_KEY, keySpec.getY()));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(ECPublicKeySpec keySpec) {
        ECParameterSpec paramSpec = keySpec.getParams();
        EcCurve curve = lookup(paramSpec);

        // Encode EC point, according to SEC 1 section 2.3.3, as an uncompressed point
        byte[] encodedPoint = encodePointUncompressed(keySpec.getW(), paramSpec);

        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()));
        params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PUB_KEY, encodedPoint));
        return params;
    }

    public static ArrayList<OSSL_PARAM> newParams(RSAPublicKeySpec keySpec) {
        ArrayList<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_N, keySpec.getModulus()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_E, keySpec.getPublicExponent()));
        return params;
    }

    static private EVP_PKEY newPriv(String name, OSSL_LIB_CTX libCtx, OsslArena arena, OSSL_PARAM... params) {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_PKEY_CTX pkeyCtx = libCtx.newPkeyCtx(name, null, confinedArena);
            pkeyCtx.fromdataInit();
            return pkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, arena, params);
        }
    }

    static private EVP_PKEY newPub(String name, OSSL_LIB_CTX libCtx, OsslArena arena, OSSL_PARAM... params) {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_PKEY_CTX pkeyCtx = libCtx.newPkeyCtx(name, null, confinedArena);
            pkeyCtx.fromdataInit();
            return pkeyCtx.fromdata(EVP_PKEY.Selection.PUBLIC_KEY, arena, params);
        }
    }
}
