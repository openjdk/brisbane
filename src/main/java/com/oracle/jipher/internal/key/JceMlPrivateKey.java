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

package com.oracle.jipher.internal.key;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Map;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newOctetString;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * Base class for Module-Lattice private keys backed by an OpenSSL {@link Pkey} instance.
 * <p>
 * This class extends {@link JceOsslPrivateKey} to share common OpenSSL key handling and to
 * support standard JCA {@code KeyFactory} usage.
 * </p>
 * The key can be explicitly destroyed, which frees the native resources and
 * prevents any further use of the key material. Once destroyed, attempts to
 * access the key (e.g. via {@link #getPkey()} or {@link #getEncoded()}) will
 * result in an {@link IllegalStateException}.
 */
public abstract sealed class JceMlPrivateKey extends JceOsslPrivateKey implements JceMlKey
        permits JceMlPrivateKey.JceMlKemPrivateKey, JceMlPrivateKey.JceMlDsaPrivateKey {

    public enum EncodingScheme {
        SEED, EXPANDEDKEY, BOTH
    }

    final EncodingScheme encodingScheme;
    final String mlAlgoName;
    private volatile int hashCode = 0;

    /**
     * Creates a new Module-Lattice private key.
     *
     * @param pkey the native OpenSSL public key representation
     * @param mlAlgoFamilyName the algorithm family name, one of ML-KEM or ML-DSA
     * @param mlAlgoName the specific algorithm name, such as ML-KEM-512 or ML-DSA-65
     * @param scheme the encoding scheme, on of SEED, EXPANDEDKEY or BOTH
     */
    JceMlPrivateKey(Pkey pkey, String mlAlgoFamilyName, String mlAlgoName, EncodingScheme scheme) {
        super(mlAlgoFamilyName, pkey);
        this.encodingScheme = scheme;
        this.mlAlgoName = mlAlgoName;
    }

    /*
     * Private Key Encoding scheme is bound to the key at creation time in alignment
     * with JDK behavior.
     */
    @Override
    byte[] derEncode() throws InvalidKeyException {
        Map<String, byte[]> keyParams = this.pkey.getMLPrivKeyData(true);
        byte[] seed = keyParams.get(EVP_PKEY.PKEY_PARAM_ML_SEED);
        byte[] expandedKey = keyParams.get(EVP_PKEY.PKEY_PARAM_PRIV_KEY);
        try {
            // See RFC 9935 and RFC 9881, Section 6.
            byte[] privateKeyPayload = switch (this.encodingScheme) {
                case SEED -> {
                    if (seed == null) {
                        throw new InvalidKeyException("Seed unavailable");
                    }
                    Asn1BerValue seedDer = Asn1.implicit(0).newOctetString(seed);
                    yield seedDer.encodeDerOctets();
                }
                case EXPANDEDKEY -> {
                    if (expandedKey == null) {
                        throw new InvalidKeyException("Expanded Key unavailable");
                    }
                    yield newOctetString(expandedKey).encodeDerOctets();
                }
                case BOTH -> {
                    if (seed == null || expandedKey == null) {
                        throw new InvalidKeyException("Seed and/or Expanded unavailable");
                    }
                    yield Asn1.newSequence(
                            Asn1.newOctetString(seed),
                            Asn1.newOctetString(expandedKey)).encodeDerOctets();
                }
            };

            Asn1BerValue mlKEMPrivKey = newSequence(
                    // version Version
                    newInteger(0),
                    // alg id
                    newSequence(getAlgId(variant())),
                    // privateKey octet string
                    newOctetString(privateKeyPayload));

            return mlKEMPrivKey.encodeDerOctets();
        } finally {
            Util.clearArrays(seed, expandedKey);
        }
    }

    /**
     * Returns the variant (ML-KEM or ML-DSA) of this ML key
     *
     * @return the ML key variant
     */
    @Override
    public String variant() {
        return this.mlAlgoName;
    }

    /**
     * Returns the parameters associated with this key.
     *
     * @return the associated parameters
     */
    @Override
    public AlgorithmParameterSpec getParams() {
        return new NamedParameterSpec(variant());
    }

    private byte[] canonicalRep() throws InvalidKeyException {
        Map<String, byte[]> keyParams = this.pkey.getMLPrivKeyData(false);
        return keyParams.get(EVP_PKEY.PKEY_PARAM_PUB_KEY);
    }

    @Override
    public int hashCode() {
        int result = this.hashCode;
        if (result == 0) {
            try {
                byte[] canonicalRep = canonicalRep();
                result = Util.hashCode(canonicalRep);
                this.hashCode = result;
            } catch (Exception e) {
                // Do nothing
            }
        }
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        JceMlPrivateKey other = (JceMlPrivateKey) obj;
        try {
            byte[] thisRep = this.canonicalRep();
            byte[] thatRep = other.canonicalRep();
            return Util.equalsCT(thisRep, thatRep);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ML-KEM private key backed by an OpenSSL {@link Pkey} instance.
     */
    public static final class JceMlKemPrivateKey extends JceMlPrivateKey {

        /**
         * Creates a new ML-KEM private key.
         *
         * @param mlKemAlgoName the ML-KEM algorithm name, such as ML-KEM-512, ML-KEM-768, or ML-KEM-1024
         * @param pkey the native OpenSSL private key representation
         */
        public JceMlKemPrivateKey(String mlKemAlgoName, Pkey pkey) {
            super(pkey, ML_KEM_ALGO_FAMILY_NAME, mlKemAlgoName, ToolkitProperties.getMLKEMEncodingScheme());
        }

        @Override
        public String getAlgorithm() {
            return ML_KEM_ALGO_FAMILY_NAME;
        }
    }

    /**
     * ML-DSA private key backed by an OpenSSL {@link Pkey} instance.
     */
    public static final class JceMlDsaPrivateKey extends JceMlPrivateKey {

        /**
         * Creates a new ML-DSA private key.
         *
         * @param mlDsaAlgoName the ML-DSA algorithm name, such as ML-DSA-44, ML-DSA-65, or ML-DSA-87
         * @param pkey the native OpenSSL private key representation
         */
        public JceMlDsaPrivateKey(String mlDsaAlgoName, Pkey pkey) {
            super(pkey, ML_DSA_ALGO_FAMILY_NAME, mlDsaAlgoName, ToolkitProperties.getMLDSAEncodingScheme());
        }
    }
}
