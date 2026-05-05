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
import java.security.InvalidKeyException;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.spi.DHFIPSParameterSpec;
import com.oracle.jipher.internal.spi.DHFIPSParameterValidationSpec;

import static com.oracle.jipher.internal.common.EcUtil.InvalidUncompressedECPoint;
import static com.oracle.jipher.internal.common.EcUtil.decodePointUncompressed;
import static com.oracle.jipher.internal.common.EcUtil.encodePointUncompressed;


/**
 * Pkey object.
 * <p>This class assumes that all components of imported keys are non-negative values.  It thus always employs
 *    OSSL_PARAM.ofUnsigned(String, BigInteger)
 * or OSSL_PARAM.ofUnsignedIntegerBytes(String, byte[])
 * when passing a big integer to OpenSSL.  The caller of methods in this class, typically the SPI layer, should
 * validate inputs to ensure that negative values are rejected.
 * <p>Note: Since commit f171985, which first appeared in OpenSSL 3.2.0, OpenSSL supports importing signed integer
 *       OSSL_PARAMs.  However, cryptographic algorithm implementations that take an asymmetric key as an input
 *       do NOT support keys with negative components. For example, the BN_mod_exp implementations ignore the sign
 *       of the exponent.  Processing a key with a negative component thus produces an unexpected result,
 *       often without reporting any error.
 */
public class Pkey implements AutoCloseable {

    enum KeyType {
        RSA, DH, DSA, EC, ML
    }

    enum ContentType {
        KEY_PARAMETERS,
        PUBLIC_KEY,
        KEY_PAIR
    }

    // 'MAX_PKEY_PARAM_EC_COORD_BIGNUM_BYTES' defines an allocation large enough to receive any requested
    // value of an EC point co-ordinate (in practice) for curves up to secp521.
    private static final int MAX_PKEY_PARAM_EC_COORD_BIGNUM_BYTES = (521 + 7) / 8;

    private static final OSSL_PARAM PKEY_PARAM_TEMPLATE_EC_PUB_X =
            OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_EC_PUB_X, OSSL_PARAM.Type.UNSIGNED_INTEGER, MAX_PKEY_PARAM_EC_COORD_BIGNUM_BYTES);

    private static final OSSL_PARAM PKEY_PARAM_TEMPLATE_EC_PUB_Y =
            OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_EC_PUB_Y, OSSL_PARAM.Type.UNSIGNED_INTEGER, MAX_PKEY_PARAM_EC_COORD_BIGNUM_BYTES);

    private static final int MAX_GROUP_NAME_BYTES = 64;
    private static final OSSL_PARAM PKEY_PARAM_TEMPLATE_GROUP_NAME =
            OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, OSSL_PARAM.Type.UTF8_STRING, MAX_GROUP_NAME_BYTES);

    private final KeyType keyType;
    private final String keyAlgoName;
    private final ContentType contentType;
    private final EVP_PKEY evpPkey;

    /**
     * Helper method to free Pkey objects if not null.
     * @param pkeys one or more pkeys to free
     */
    public static void free(Pkey... pkeys) {
        if (pkeys != null) {
            for (Pkey pk : pkeys) {
                if (pk != null) {
                    pk.free();
                }
            }
        }
    }

    /**
     * Destroys (zero-clears) sensitive parameters in a list of parameters
     * @param params list of parameters
     */
    static void destroySensitive(List<OSSL_PARAM> params) {
        if (params != null) {
            for (OSSL_PARAM param : params) {
                if (param.sensitive) {
                    param.destroy();
                }
            }
        }
    }

    /**
     * Gets a copy of the value of an OSSL_PARAM as a byte[] containing a two's-complement representation of
     * an Integer in big-endian byte-order.
     * @throws IllegalArgumentException If the OSSL_PARAM is not an INTEGER or UNSIGNED_INTEGER type
     */
    static byte[] getIntegerBytes(OSSL_PARAM param) {
        if (param.dataType == OSSL_PARAM.Type.INTEGER) {
            return param.byteArrayValue(); // Returns a copy of the data byte array.
        } else if (param.dataType == OSSL_PARAM.Type.UNSIGNED_INTEGER) {
            // If the most significant bit of the most significant byte is set then prefix a zero-byte.
            boolean zeroExtend = (param.data[0] & (byte) 0x80) != 0;
            byte[] value = new byte[zeroExtend ? param.data.length + 1 : param.data.length];
            System.arraycopy(param.data, 0, value, zeroExtend ? 1 : 0, param.data.length);
            return value;
        } else {
            throw new IllegalArgumentException("Unsupported data type: " + param.dataType);
        }
    }

    /**
     * Creates a PKey of the specified type to encapsulate an EVP_PKEY
     *
     * @param keyType the type of the EVP_PKEY
     * @param keyAlgoName algorithm associated with the key
     * @param contentType the selection of components backing the EVP_PKEY
     * @param createEvpPkey a function that creates a (to be encapsulated) EVP_PKEY in a specified arena
     */
    Pkey(KeyType keyType, String keyAlgoName, ContentType contentType, Function<OsslArena, EVP_PKEY> createEvpPkey) {
        this.keyType = keyType;
        this.keyAlgoName = keyAlgoName;
        this.contentType = contentType;
        this.evpPkey = createEvpPkey.apply(OsslArena.ofAuto());
    }

    /**
     * Creates a PKey of the specified type to encapsulate an EVP_PKEY
     *
     * @param keyType the type of the EVP_PKEY
     * @param contentType the selection of components backing the EVP_PKEY
     * @param createEvpPkey a function that creates a (to be encapsulated) EVP_PKEY in a specified arena
     */
    Pkey(KeyType keyType, ContentType contentType, Function<OsslArena, EVP_PKEY> createEvpPkey) {
        this(keyType, typeToName(keyType), contentType, createEvpPkey);
    }

    public void free() {
        close();
    }

    public void close() {
        this.evpPkey.free();
    }

    /**
     * Create a new Pkey object containing the public key of this object.
     * @return the new public Pkey object
     * @throws InvalidKeyException if an error occurred performing this operation
     */
    Pkey createPub() throws InvalidKeyException {
        // There is no need to call this.evpPkey.isA(<type>) because the encompassing object knows the type
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            OsslParamBuffer paramBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PUBLIC_KEY, confinedArena);
            return newPub(this.keyType, this.keyAlgoName, paramBuffer);
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create " + this.keyType + " public key from key pair", e);
        }
    }


    /**
     * Get the Pkey key type.
     * @return the type
     */
    KeyType getKeyType() {
        return this.keyType;
    }

    /**
     * Get the Algorithm name associated with this pkey.
     * @return key algorithm name
     */
    String getKeyAlgoName() {
        return this.keyAlgoName;
    }
    /**
     * Get the Pkey content type.
     * @return the content type
     */
    ContentType getContentType() {
        return this.contentType;
    }

    /**
     * Get the Pkey's EVP_PKEY.
     * @return the EVP_PKEY
     */
    EVP_PKEY getEvpPkey() {
        return this.evpPkey;
    }

    /**
     * Create a Pkey object that encapsulates a reference to the EVP_PKEY encapsulated by an existing Pkey object.
     * @param pkey the existing Pkey object
     * @return a new Pkey object that encapsulates a reference to the EVP_PKEY encapsulated by the specified Pkey
     */
    public static Pkey createReference(Pkey pkey) {
        return new Pkey(pkey.getKeyType(), pkey.getKeyAlgoName(), pkey.getContentType(), arena -> pkey.getEvpPkey().upRef(arena));
    }

    /**
     * Create a new Pkey RSA public key using the specified public key data.
     * @param n the modulus n, as a non-negative BigInteger
     * @param e the public exponent e, as non-negative BigInteger
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newRsaPub(BigInteger n, BigInteger e) throws InvalidKeyException {
        try {
            OSSL_PARAM nParam = OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_N, n);
            OSSL_PARAM eParam = OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_E, e);
            return newPub(KeyType.RSA, nParam, eParam);
        } catch (OpenSslException ex) {
            throw new InvalidKeyException("Failed to create RSA public key", ex);
        }
    }

    /**
     * Create a new Pkey RSA private key using the specified RSA private Key CRT specification.
     * @param spec an RSAPrivateCrtKeySpec containing non-negative key components
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newRsaPriv(RSAPrivateCrtKeySpec spec) throws InvalidKeyException {
        List<OSSL_PARAM> params = new ArrayList<>();
        try {
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_N, spec.getModulus()));
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_E, spec.getPublicExponent()));
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_D, spec.getPrivateExponent()).sensitive());
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_FACTOR1, spec.getPrimeP()).sensitive());
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_FACTOR2, spec.getPrimeQ()).sensitive());
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT1, spec.getPrimeExponentP()).sensitive());
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT2, spec.getPrimeExponentQ()).sensitive());
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_COEFFICIENT1, spec.getCrtCoefficient()).sensitive());
            return newPriv(KeyType.RSA, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create RSA private key", e);
        } finally {
            destroySensitive(params);
        }
    }

    /**
     * Create a new Pkey RSA private key using the specified RSA private CRT key data.
     * Each <code>byte[]</code> parameter should contain an unsigned integer in big-endian byte-order: the most
     * significant byte is in the zeroth element.
     *
     * @param n the modulus n
     * @param e the public exponent e
     * @param d the private exponent d
     * @param p the prime factor p
     * @param q the prime factor q
     * @param expP the CRT exponent for p
     * @param expQ the CRT exponent for q
     * @param crtCoef the CRT coefficient
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newRsaPriv(byte[] n, byte[] e, byte[] d,
                                  byte[] p, byte[] q, byte[] expP, byte[] expQ,
                                  byte[] crtCoef) throws InvalidKeyException {
        try {
            return newPriv(KeyType.RSA,
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_N, n),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_E, e),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_D, d).sensitive(),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_FACTOR1, p).sensitive(),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_FACTOR2, q).sensitive(),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT1, expP).sensitive(),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT2, expQ).sensitive(),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_RSA_COEFFICIENT1, crtCoef).sensitive());
        } catch (OpenSslException ex) {
            throw new InvalidKeyException("Failed to create RSA private key", ex);
        }
    }

    /**
     * Create a new Pkey EC public key using the specified curve and public point data.
     * @param curve the curve
     * @param point the public key point as a pair of affine coordinates
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newEcPub(EcCurve curve, ECPoint point, ECParameterSpec paramSpec) throws InvalidKeyException {
        try {
            // Encode EC point, according to SEC 1 section 2.3.3, as an uncompressed point
            byte[] encodedPoint = encodePointUncompressed(point, paramSpec);
            return newPub(KeyType.EC,
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()),
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PUB_KEY, encodedPoint)
            );
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create EC public key", e);
        }
    }

    /**
     * Create a new Pkey EC private key using the specified curve and private value.
     * @param curve the curve
     * @param priv the private value as a non-negative BigInteger
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newEcPriv(EcCurve curve, BigInteger priv) throws InvalidKeyException {
        OSSL_PARAM privateKey = OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PRIV_KEY, priv).sensitive();
        try {
            return newPriv(KeyType.EC,
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()),
                    privateKey,
                    /* Do not attempt to encode the public key */
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_EC_INCLUDE_PUBLIC, 0));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create EC private key", e);
        }  finally {
            privateKey.destroy();
        }
    }

    /**
     * Create a new Pkey EC private key using the specified curve and private value.
     * @param curve the curve
     * @param priv a byte[] containing the EC private key as an unsigned integer in big-endian byte-order: the most
     *             significant byte is in the zeroth element
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newEcPriv(EcCurve curve, byte[] priv) throws InvalidKeyException {
        try {
            return newPriv(KeyType.EC,
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()),
                    OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_PRIV_KEY, priv).sensitive(),
                    /* Do not attempt to encode the public key */
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_EC_INCLUDE_PUBLIC, 0));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create EC private key", e);
        }
    }

    /**
     * Create a new Pkey DSA public key usage the specified parameter and key values.
     * @param spec a DSAParameterSpec containing non-negative DSA parameters
     * @param pub a non-negative DSA public key value
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newDsaPub(DSAParameterSpec spec, BigInteger pub) throws InvalidKeyException {
        try {
            return newPub(KeyType.DSA,
                    OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, spec.getP()),
                    OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_Q, spec.getQ()),
                    OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, spec.getG()),
                    OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PUB_KEY, pub));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create DSA public key", e);
        }
    }

    private static List<OSSL_PARAM> toOsslParamList(DHParameterSpec spec) {
        List<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, spec.getP()));
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, spec.getG()));
        if (spec instanceof DHFIPSParameterSpec fipsSpec) {
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_Q, fipsSpec.getQ()));
            if (fipsSpec.getJ() != null) {
                params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_COFACTOR, fipsSpec.getJ()));
            }
            DHFIPSParameterValidationSpec validationParameters = fipsSpec.getParameterValidationSpec();
            if (validationParameters != null) {
                params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_FFC_SEED, validationParameters.seed()));
                params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_FFC_PCOUNTER, validationParameters.pgenCounter()));
            }
        }
        return params;
    }

    /**
     * Create a new Pkey DH public key using the specified parameter and key values.
     * @param spec a DHParameterSpec providing non-negative DH parameters
     * @param pub a non-negative public key value
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newDhPub(DHParameterSpec spec, BigInteger pub) throws InvalidKeyException {
        try {
            List<OSSL_PARAM> params = toOsslParamList(spec);
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PUB_KEY, pub));
            return newPub(KeyType.DH, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create DH public key", e);
        }
    }

    /**
     * Create a new Pkey DH private key using the specified DH parameters and private key.
     * @param spec a DHParameterSpec providing non-negative DH parameters
     * @param prv a non-negative private key value
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newDhPriv(DHParameterSpec spec, BigInteger prv) throws InvalidKeyException {
        OSSL_PARAM privateKey = OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_PRIV_KEY, prv).sensitive();
        try {
            List<OSSL_PARAM> params = toOsslParamList(spec);
            params.add(privateKey);
            return newPriv(KeyType.DH, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create DH private key", e);
        } finally {
            privateKey.destroy();
        }
    }

    /**
     * Create a new Pkey DH private key using the specified DH parameters and private key.
     * @param spec a DHParameterSpec providing non-negative DH parameters
     * @param prv the byte[] containing the DH private key as an unsigned integer in big-endian byte-order: the most
     *            significant byte is in the zeroth element
     * @return the created Pkey
     * @throws InvalidKeyException if an error occurs creating the key using the given data
     */
    public static Pkey newDhPriv(DHParameterSpec spec, byte[] prv) throws InvalidKeyException {
        try {
            List<OSSL_PARAM> params = toOsslParamList(spec);
            params.add(OSSL_PARAM.ofUnsignedIntegerBytes(EVP_PKEY.PKEY_PARAM_PRIV_KEY, prv).sensitive());
            return newPriv(KeyType.DH, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create DH private key", e);
        }
    }

    /**
     * Create a new Pkey ML-KEM or ML-DSA private key of variant keyTypeAlg using raw
     * private key data.
     *
     * @param keyTypeAlg ML-KEM or ML-DSA variant.
     * @param seed ML private key seed bytes, or null if unavailable.
     * @param expandedKey ML private key expanded-key bytes, or null if unavailable.
     * @return The created Pkey.
     * @throws InvalidKeyException if an error occurs creating the key using the given data.
     */
    public static Pkey newMLPriv(String keyTypeAlg, byte[] seed, byte[] expandedKey) throws InvalidKeyException {
        try {
            if (seed == null && expandedKey == null) {
                throw new InvalidKeyException("Both seed and expanded key cannot be null");
            }
            List<OSSL_PARAM> params = new ArrayList<>();
            if (expandedKey != null) {
                params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PRIV_KEY, expandedKey).sensitive());
            }
            if (seed != null) {
                params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_ML_SEED, seed).sensitive());
            }
            return newPriv(KeyType.ML, keyTypeAlg, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (OpenSslException e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
     * Create a new Pkey ML-KEM or ML-DSA public key of variant keyTypeAlg using raw
     * public key bytes.
     *
     * @param keyTypeAlg ML-KEM or ML-DSA variant.
     * @param pub Raw public key bytes.
     * @return The created Pkey.
     * @throws InvalidKeyException if an error occurs creating the key using the given data.
     */
    public static Pkey newMLPub(String keyTypeAlg, byte[] pub) throws InvalidKeyException {
        try {
            List<OSSL_PARAM> params = new ArrayList<>();
            params.add(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PUB_KEY, pub));
            return newPub(KeyType.ML, keyTypeAlg, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }


    public static Pkey newEcParams(EcCurve curve) {
        return newParams(KeyType.EC, OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_GROUP_NAME, curve.sn()));
    }

    public static Pkey newDhParams(DHParameterSpec spec) {
        List<OSSL_PARAM> params = new ArrayList<>();
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_P, spec.getP()));
        if (spec instanceof DHFIPSParameterSpec fipsSpec) {
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_Q, fipsSpec.getQ()));
        }
        params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_G, spec.getG()));
        return newParams(KeyType.DH, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
    }

    private static String typeToName(KeyType type) {
        return switch (type) {
            case RSA -> "RSA";
            case DH -> "DH";
            case DSA -> "DSA";
            case EC -> "EC";
            case ML -> "ML";
        };
    }

    private static Pkey newPub(KeyType type, String keyAlgo, OsslParamBuffer paramBuffer) {
        return new Pkey(type, keyAlgo, ContentType.PUBLIC_KEY, arena -> {
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                EVP_PKEY_CTX evpPkeyCtx = LibCtx.newPkeyCtx(keyAlgo, confinedArena);
                evpPkeyCtx.fromdataInit();
                return evpPkeyCtx.fromdata(EVP_PKEY.Selection.PUBLIC_KEY, arena, paramBuffer);
            }
        });
    }

    private static Pkey newPub(KeyType type, OSSL_PARAM... params) {
        assert type != KeyType.ML;
        return newPub(type, typeToName(type), params);
    }

    private static Pkey newPub(KeyType type, String keyAlgo, OSSL_PARAM... params) {
        return new Pkey(type, keyAlgo, ContentType.PUBLIC_KEY, arena -> {
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                EVP_PKEY_CTX evpPkeyCtx = LibCtx.newPkeyCtx(keyAlgo, confinedArena);
                evpPkeyCtx.fromdataInit();
                return evpPkeyCtx.fromdata(EVP_PKEY.Selection.PUBLIC_KEY, arena, params);
            }
        });
    }

    private static Pkey newPriv(KeyType type, String keyAlgo, OSSL_PARAM... params) {
        return new Pkey(type, keyAlgo, ContentType.KEY_PAIR, arena -> {
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                EVP_PKEY_CTX evpPkeyCtx = LibCtx.newPkeyCtx(keyAlgo, confinedArena);
                evpPkeyCtx.fromdataInit();
                return evpPkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, arena, params);
            }
        });
    }

    private static Pkey newPriv(KeyType type, OSSL_PARAM... params) {
        assert type != KeyType.ML;
        return newPriv(type, typeToName(type), params);
    }

    private static Pkey newParams(KeyType type, OSSL_PARAM... params) {
        String keyAlgo = typeToName(type);
        return new Pkey(type, keyAlgo, ContentType.KEY_PARAMETERS, arena -> {
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                EVP_PKEY_CTX evpPkeyCtx = LibCtx.newPkeyCtx(keyAlgo, confinedArena);
                evpPkeyCtx.fromdataInit();
                return evpPkeyCtx.fromdata(EVP_PKEY.Selection.KEY_PARAMETERS, arena, params);
            }
        });
    }

    /**
     * Returns the modulus from this (RSA) Pkey.
     */
    public BigInteger getRsaModulus() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_N, false);
    }

    /**
     * Returns the public exponent from this (RSA) Pkey.
     */
    public BigInteger getRsaPublicExponent() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_E, false);
    }

    /**
     * Returns the public exponent from this (RSA) Pkey.
     */
    public BigInteger getRsaPrivateExponent() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_D, true);
    }

    /**
     * Returns the prime P from this (RSA) Pkey.
     */
    public BigInteger getRsaPrimeP() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_FACTOR1, true);
    }

    /**
     * Returns the prime Q from this (RSA) Pkey.
     */
    public BigInteger getRsaPrimeQ() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_FACTOR2, true);
    }

    /**
     * Returns the prime exponent P from this (RSA) Pkey.
     */
    public BigInteger getRsaPrimeExponentP() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT1, true);
    }

    /**
     * Returns the prime exponent Q from this (RSA) Pkey.
     */
    public BigInteger getRsaPrimeExponentQ() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_EXPONENT2, true);
    }

    /**
     * Returns the Chinese Remainder Theorem (CRT) coefficient from this (RSA) Pkey.
     */
    public BigInteger getRsaCrtCoefficient() {
        return getRsaParam(EVP_PKEY.PKEY_PARAM_RSA_COEFFICIENT1, true);
    }

    private BigInteger getRsaParam(String param, boolean sensitive) {
        if (this.keyType != KeyType.RSA) {
            throw new IllegalStateException("Cannot retrieve " + param + " from " + this.keyType + " key");
        }

        EVP_PKEY.Selection selection;
        if ((param.equals(EVP_PKEY.PKEY_PARAM_RSA_N) || param.equals(EVP_PKEY.PKEY_PARAM_RSA_E))) {
            if (this.contentType == ContentType.KEY_PARAMETERS) {
                throw new IllegalStateException("Cannot retrieve " + param + " from " + this.keyType + " " + this.contentType);
            }
            selection = EVP_PKEY.Selection.PUBLIC_KEY;
        } else {
            if (this.contentType != ContentType.KEY_PAIR) {
                throw new IllegalStateException("Cannot retrieve " + param + " from " + this.keyType + " " + this.contentType);
            }
            selection = EVP_PKEY.Selection.PKEY_KEYPAIR;
        }

        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(selection, osslArena);
            // This call should never throw NoSuchElementException
            OSSL_PARAM osslParam = osslParamBuffer.locate(param).orElseThrow();
            try {
                return osslParam.bigIntegerValue();
            } finally {
                if (sensitive) {
                    osslParam.destroy();
                }
            }
        }
    }

    static final String[] RSA_PARAM_KEYS = new String[] {
            EVP_PKEY.PKEY_PARAM_RSA_N,
            EVP_PKEY.PKEY_PARAM_RSA_E,
            EVP_PKEY.PKEY_PARAM_RSA_D,
            EVP_PKEY.PKEY_PARAM_RSA_FACTOR1,
            EVP_PKEY.PKEY_PARAM_RSA_FACTOR2,
            EVP_PKEY.PKEY_PARAM_RSA_EXPONENT1,
            EVP_PKEY.PKEY_PARAM_RSA_EXPONENT2,
            EVP_PKEY.PKEY_PARAM_RSA_COEFFICIENT1,
    };

    /**
     * Returns the RSA key data for this Pkey if this is an RSA Pkey storing a key pair
     * The returned array is of length 8. Each of the 8 byte[]'s will contain a two's-complement representation of
     * an Integer in big-endian byte-order: the most significant byte is in the zeroth element.
     * @return byte[][] containing
     * <ul>
     *  <li> index 0: modulus </li>
     *  <li> index 1: public exponent </li>
     *  <li> index 2: private exponent </li>
     *  <li> index 3: prime factor p </li>
     *  <li> index 4: prime factor q </li>
     *  <li> index 5: CRT exponent for p </li>
     *  <li> index 6: CRT exponent for q </li>
     *  <li> index 7: CRT coefficient </li>
     * </ul>
     * @throws InvalidKeyException if an error occurred retrieving the key data
     */
    public byte[][] getRsaPrivateKeyData() throws InvalidKeyException {
        if (this.keyType != KeyType.RSA || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException("Cannot retrieve RSA private key data from " + this.keyType + " " + this.contentType);
        }
        byte[][] params = new byte[RSA_PARAM_KEYS.length][];
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            int index = 0;
            for (String rsaParamKey : RSA_PARAM_KEYS) {
                // This call should never throw NoSuchElementException
                OSSL_PARAM osslParam = osslParamBuffer.locate(rsaParamKey).orElseThrow();
                try {
                    params[index++] = getIntegerBytes(osslParam);
                } finally {
                    osslParam.destroy();
                }
            }
            return params;
        } catch (OpenSslException e) {
            Util.clearArrays(params);
            throw new InvalidKeyException("Failed to retrieve RSA private key data", e);
        }
    }
    /**
     * Returns the ML Private key parameter data for this Pkey.
     * If all is true then seed, expandedKey and public key data are returned.
     * If all is false, then only non-sensitive data (public key data) is returned.
     * @throws InvalidKeyException if an error occurs retrieving the key data
     */
    public Map<String, byte[]> getMLPrivKeyData(boolean all) throws InvalidKeyException {
        if (this.keyType != KeyType.ML || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException(
                    "Cannot retrieve ML private key data from " + this.keyType + " " + this.contentType);
        }

        OSSL_PARAM osslParamExpanded = null;
        OSSL_PARAM osslParamSeed = null;
        OSSL_PARAM osslParamPub;
        Map<String, byte[]> paramMap = new HashMap<>();
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            Optional<OSSL_PARAM> osslParam;
            if (all) {
                osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PRIV_KEY);
                if (osslParam.isPresent()) {
                    osslParamExpanded = osslParam.get();
                    paramMap.put(EVP_PKEY.PKEY_PARAM_PRIV_KEY, osslParamExpanded.byteArrayValue());
                }
                osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_ML_SEED);
                if (osslParam.isPresent()) {
                    osslParamSeed = osslParam.get();
                    paramMap.put(EVP_PKEY.PKEY_PARAM_ML_SEED, osslParamSeed.byteArrayValue());
                }
            }
            osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PUB_KEY);
            if (osslParam.isPresent()) {
                osslParamPub = osslParam.get();
                paramMap.put(EVP_PKEY.PKEY_PARAM_PUB_KEY, osslParamPub.byteArrayValue());
            }
            return paramMap;
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        } finally {
            if (osslParamExpanded != null) {
                osslParamExpanded.destroy();
            }
            if (osslParamSeed != null) {
                osslParamSeed.destroy();
            }
        }
    }

    /**
     * Returns the ML Public key data for this Pkey.
     *
     * @throws InvalidKeyException if an error occurs retrieving the key data
     */
    public byte[] getMLPubKeyData() throws InvalidKeyException {
        if (this.keyType != KeyType.ML || this.contentType == ContentType.KEY_PARAMETERS) {
            throw new IllegalStateException(
                    "Cannot retrieve ML public key data from " + this.keyType + " " + this.contentType);
        }

        OSSL_PARAM osslParam = null;
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PUBLIC_KEY, osslArena);
            osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PUB_KEY).orElseThrow();
            return osslParam.byteArrayValue();
        } catch (Exception e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
     * Returns the EC Private key value for this Pkey as a BigInteger if this is an EC Pkey storing a key pair
     * @return the private key value as a big integer
     */
    public BigInteger getEcPrivateKeyAsBigInteger() {
        if (this.keyType != KeyType.EC || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException("Cannot retrieve EC private key from " + this.keyType + " " + this.contentType);
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            // This should never throw NoSuchElementException
            OSSL_PARAM osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PRIV_KEY).orElseThrow();
            try {
                return osslParam.bigIntegerValue();
            } finally {
                osslParam.destroy();
            }
        }
    }

    /**
     * Returns the EC Private key value for this Pkey as a <code>byte[]</code> if this is an EC Pkey
     * storing a key pair
     * @return a <code>byte[]</code> containing the EC private key value as a two's-complement representation of an
     *         Integer in big-endian byte-order: the most significant byte is in the zeroth element
     * @throws IllegalStateException if this is not an EC Pkey storing a key pair
     */
    public byte[] getEcPrivateKeyAsByteArray() {
        if (this.keyType != KeyType.EC || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException("Cannot retrieve EC private key from " + this.keyType + " " + this.contentType);
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            // This call should never throw NoSuchElementException
            OSSL_PARAM osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PRIV_KEY).orElseThrow();
            try {
                return getIntegerBytes(osslParam);
            } finally {
                osslParam.destroy();
            }
        }
    }

    /**
     * Returns the named Curve for this Pkey.
     * @return the EcCurve
     * @throws InvalidKeyException if an error occurred retrieving the key data
     */
    public EcCurve getEcCurve() throws InvalidKeyException {
        if (this.keyType != KeyType.EC) {
            throw new IllegalStateException("Cannot retrieve EC curve from " + this.keyType + " key");
        }

        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer;
            String sn;
            try {
                osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.KEY_PARAMETERS, osslArena);
                // This call should never throw NoSuchElementException
                sn = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_GROUP_NAME).orElseThrow().stringValue();
            } catch (OpenSslException e) {
                // OpenSSL PR #17981 fixed a bug that prevented EVP_PKEY_todata from exporting of ec parameters
                // The fix first appeared on 3.0.3. For older versions we must fall back to using EVP_PKEY_get_params
                sn = (this.evpPkey.getParams(PKEY_PARAM_TEMPLATE_GROUP_NAME)[0]).stringValue();
            }
            EcCurve curve = EcCurve.bySn(sn);
            if (curve == null) {
                throw new InvalidKeyException("Unsupported EC curve");
            }
            return curve;
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to retrieve EC curve", e);
        }
    }

    /**
     * Returns the public key point for this Pkey.
     * @return an ECPoint containing affine coordinate X and affine coordinate Y
     * @throws InvalidKeyException if an error occurred retrieving the key data
     */
    public ECPoint getEcPublicKey() throws InvalidKeyException {
        if (this.keyType != KeyType.EC || this.contentType == ContentType.KEY_PARAMETERS) {
            throw new IllegalStateException("Cannot retrieve EC public key from " + this.keyType + " " + this.contentType);
        }

        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PUBLIC_KEY, osslArena);
            // This call should never throw NoSuchElementException
            OSSL_PARAM param = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PUB_KEY).orElseThrow();
            try {
                // Since OpenSSL commit 999509c, which first appeared in version 3.0.8,
                // EC pubkeys are exported in uncompressed format by default
                return decodePointUncompressed(param.byteArrayValue());
            } catch (InvalidUncompressedECPoint e) {
                // Older versions of OpenSSL export EC pubkeys in compressed format
                OSSL_PARAM[] params = this.evpPkey.getParams(PKEY_PARAM_TEMPLATE_EC_PUB_X, PKEY_PARAM_TEMPLATE_EC_PUB_Y);
                BigInteger x = params[0].bigIntegerValue();
                BigInteger y = params[1].bigIntegerValue();
                return new ECPoint(x, y);
            }
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to retrieve EC public key", e);
        }
    }

    /**
     * Get the DH parameter values if this is a DH Pkey object.
     * @return DHParameterSpec containing DH parameter values.
     *         If Q is available the returned DHParameterSpec is a DHFIPSParameterSpec
     * @throws InvalidKeyException if an error occurs getting parameters
     */
    public DHParameterSpec getDhParams() throws InvalidKeyException {
        if (this.keyType != KeyType.DH) {
            throw new IllegalStateException("Cannot retrieve DH parameters from a " + this.keyType + " key");
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.KEY_PARAMETERS, osslArena);
            // NoSuchElementException should never be thrown by either of the following calls
            BigInteger p = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_FFC_P).orElseThrow().bigIntegerValue();
            BigInteger g = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_FFC_G).orElseThrow().bigIntegerValue();
            Optional<OSSL_PARAM> param = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_FFC_Q);
            if (param.isPresent()) {
                BigInteger q = param.get().bigIntegerValue();
                return new DHFIPSParameterSpec(p, q, g);
            } else {
                return new DHParameterSpec(p, g);
            }
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to retrieve DH parameters", e);
        }
    }

    /**
     * Get the DH public key value if this is a DH Pkey object.
     * @return the DH public key value in BigInteger representation
     * @throws InvalidKeyException if an error occurs getting parameters
     */
    public BigInteger getDhPublicKey() throws InvalidKeyException {
        if (this.keyType != KeyType.DH || this.contentType == ContentType.KEY_PARAMETERS) {
            throw new IllegalStateException("Cannot retrieve DH public key from " + this.keyType + " " + this.contentType);
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PUBLIC_KEY, osslArena);
            // NoSuchElementException should never be thrown
            return osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PUB_KEY).orElseThrow().bigIntegerValue();
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to retrieve DH public key", e);
        }
    }

    /**
     * Get the DH private key value as a <code>BigInteger</code> if this is a DH Pkey object storing a key pair.
     * @return the DH private key value in <code>BigInteger</code> representation
     */
    public BigInteger getDhPrivateKeyAsBigInteger() {
        if (this.keyType != KeyType.DH || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException("Cannot retrieve DH private key from " + this.keyType + " " + this.contentType);
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            // NoSuchElementException should never be thrown
            OSSL_PARAM osslParam  = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PRIV_KEY).orElseThrow();
            try {
                return osslParam.bigIntegerValue();
            } finally {
                osslParam.destroy();
            }
        }
    }

    /**
     * Get the DH private key value as a <code>byte[]</code> if this is a DH Pkey object storing a key pair.
     * @return a <code>byte[]</code> containing the DH private key value as a two's-complement representation of an
     *         Integer in big-endian byte-order: the most significant byte is in the zeroth element
     */
    public byte[] getDhPrivateKeyAsByteArray() {
        if (this.keyType != KeyType.DH || this.contentType != ContentType.KEY_PAIR) {
            throw new IllegalStateException("Cannot retrieve DH private key from " + this.keyType + " " + this.contentType);
        }
        try (OsslArena osslArena = OsslArena.ofConfined()) {
            OsslParamBuffer osslParamBuffer = this.evpPkey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, osslArena);
            // This call should never throw NoSuchElementException
            OSSL_PARAM osslParam = osslParamBuffer.locate(EVP_PKEY.PKEY_PARAM_PRIV_KEY).orElseThrow();
            try {
                return getIntegerBytes(osslParam);
            } finally {
                osslParam.destroy();
            }
        }
    }
}
