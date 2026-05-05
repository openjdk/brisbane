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

package com.oracle.jipher.internal.spi;

import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;

import com.oracle.jipher.internal.asn1.Asn1Exception;
import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.common.MlUtil;
import com.oracle.jipher.internal.common.MlUtil.PrivateKeyData;
import com.oracle.jipher.internal.common.MlUtil.PublicKeyData;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.key.JceMlKey;
import com.oracle.jipher.internal.key.JceMlKey.Algorithm;
import com.oracle.jipher.internal.key.JceMlPrivateKey;
import com.oracle.jipher.internal.key.JceMlPrivateKey.JceMlDsaPrivateKey;
import com.oracle.jipher.internal.key.JceMlPrivateKey.JceMlKemPrivateKey;
import com.oracle.jipher.internal.key.JceMlPublicKey.JceMlDsaPublicKey;
import com.oracle.jipher.internal.key.JceMlPublicKey.JceMlKemPublicKey;
import com.oracle.jipher.internal.openssl.Pkey;


public abstract sealed class MlKeyFactory extends AsymKeyFactory
        permits MlKeyFactory.MlKemKeyFactory, MlKeyFactory.MlDsaKeyFactory {

    private static final Debug DEBUG = Debug.getInstance("jipher");

    final Algorithm alg;
    final boolean isGeneric;

    MlKeyFactory(Algorithm alg) {
        this.alg = alg;
        this.isGeneric = this.alg == null;
    }

    /**
     * Create a PublicKey object from the given Pkey.
     *
     * @param pkey   The Pkey.
     * @param pubDer The ASN.1 DER encoding of the key.
     * @return A new PublicKey.
     * @throws InvalidKeyException Error occurred creating key object.
     */
    abstract PublicKey createPublicKey(Algorithm alg, Pkey pkey, byte[] pubDer) throws InvalidKeyException;

    /**
     * Create a PrivateKey object from the given Pkey.
     *
     * @param pkey The Pkey.
     * @return A new PrivateKey.
     * @throws InvalidKeyException Error occurred creating key object.
     */
    abstract PrivateKey createPrivateKey(Algorithm alg, Pkey pkey) throws InvalidKeyException;

    @Override
    PrivateKey generatePrivateInternal(byte[] privDer) throws InvalidKeyException {
        byte[] seed = null;
        byte[] expandedKey = null;
        try {
            PrivateKeyData prvData = MlUtil.decodePrivateKey(privDer);

            Optional<Algorithm> algDecoded = JceMlKey.find(prvData.algOid());
            if (algDecoded.isEmpty() || !isSupportedAlgorithm(algDecoded.get())) {
                throw new InvalidKeyException("Unsupported algorithm " + prvData.algOid());
            }
            Algorithm algInDer = algDecoded.get();

            // If the Key Factory is strongly bound, check that algorithms match.
            if (!isGeneric) {
                if (algInDer != alg) {
                    throw new InvalidKeyException("Use correct Key Factory type for " + algInDer.getAlgName());
                }
            }

            seed = prvData.seed();
            expandedKey = prvData.expandedKey();

            if (seed != null && seed.length != algInDer.getSeedSize()) {
                String exceptionMessage = String.format("Incorrect seed length %d for algorithm %s", seed.length,
                        algInDer.getAlgName());
                throw new InvalidKeyException(exceptionMessage);
            }
            if (expandedKey != null && expandedKey.length != algInDer.getExpandedKeySize()) {
                String exceptionMessage = String.format("Incorrect expanded key length %d for algorithm %s",
                        expandedKey.length, algInDer.getAlgName());
                throw new InvalidKeyException(exceptionMessage);
            }
            Pkey pkey = Pkey.newMLPriv(algInDer.getAlgName(), seed, expandedKey);

            return createPrivateKey(algInDer, pkey);

        } catch (Asn1Exception | IllegalArgumentException e) {
            throw new InvalidKeyException(e);
        } finally {
            Util.clearArray(seed);
            Util.clearArray(expandedKey);
        }
    }

    @Override
    protected final <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null || keySpec == null) {
            return null;
        }
        byte[] keyDer = null;
        try {
            Key jipherKey = engineTranslateKey(key);
            keyDer = key.getEncoded();
            if (jipherKey instanceof JceMlPrivateKey) {
                if (keySpec == PKCS8EncodedKeySpec.class) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(keyDer));
                } else {
                    throw new InvalidKeyException("Unknown KeySpec " + keySpec.getName());
                }
            } else {
                if (keySpec == X509EncodedKeySpec.class) {
                    return keySpec.cast(new X509EncodedKeySpec(keyDer));
                } else {
                    throw new InvalidKeyException("Unknown KeySpec " + keySpec.getName());
                }
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e);
        } finally {
            // Both keySpec clone keyDer. Zeroize it.
            if (keyDer != null) {
                Arrays.fill(keyDer, (byte) 0);
            }
        }
    }

    @Override
    PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException {
        try {
            PublicKeyData pubData = MlUtil.decodePublicKey(pubDer);
            Optional<Algorithm> algDecoded = JceMlKey.find(pubData.algOid());
            if (algDecoded.isEmpty() || !isSupportedAlgorithm(algDecoded.get())) {
                throw new InvalidKeyException("Unsupported algorithm " + pubData.algOid());
            }
            Algorithm algInDer = algDecoded.get();
            // If the Key Factory is strongly bound, check that algorithms
            // match.
            if (!this.isGeneric) {
                if (algInDer != this.alg) {
                    throw new InvalidKeyException("Use correct Key Factory type");
                }
            }

            Pkey pkey = Pkey.newMLPub(algInDer.getAlgName(), pubData.pubKeyPayload());

            return createPublicKey(algInDer, pkey, pubDer);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException(e);
        }
    }

    abstract boolean isSupportedAlgorithm(Algorithm alg);

    public sealed static class MlKemKeyFactory extends MlKeyFactory
            permits MlKemKeyFactory512, MlKemKeyFactory768, MLKemKeyFactory1024 {

        public MlKemKeyFactory() {
            super(null);
        }

        MlKemKeyFactory(Algorithm algBound) {
            super(algBound);
        }

        @Override
        PrivateKey createPrivateKey(Algorithm alg, Pkey pkey) throws InvalidKeyException {
            return new JceMlKemPrivateKey(alg.getAlgName(), pkey);
        }

        @Override
        PublicKey createPublicKey(Algorithm alg, Pkey pkey, byte[] pubDer) throws InvalidKeyException {
            return new JceMlKemPublicKey(alg.getAlgName(), pkey, pubDer);
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            byte[] rawBytes = RawKeySpec.getKeyArr(keySpec);
            if (rawBytes == null) {
                return super.engineGeneratePublic(keySpec);
            }
            // Raw public Key Bytes do not carry Algorithm information.
            // We can discern from size but better to fail in case
            // generic key factory is used.
            try {
                if (this.isGeneric) {
                    throw new InvalidKeySpecException("RawKeySpec cannot be used with generic ML-KEM KeyFactory");
                }
                Pkey pkey = Pkey.newMLPub(this.alg.getAlgName(), rawBytes);

                return createPublicKey(this.alg, pkey, null);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        }

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (key instanceof JceMlKemPrivateKey || key instanceof JceMlKemPublicKey) {
                if (this.isGeneric) {
                    return key;
                } else {
                    // check if right factory is used.
                    String variant = ((JceMlKey) key).variant();
                    if (variant.equals(this.alg.getAlgName())) {
                        return key;
                    } else {
                        throw new InvalidKeyException("Use correct Key Factory type");
                    }
                }
            } else if (key instanceof PrivateKey prvK) {
                return translatePrivate(prvK);
            } else if (key instanceof PublicKey pubK) {
                return translatePublic(pubK);
            } else {
                throw new InvalidKeyException("Could not translate ML-KEM Key");
            }
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_KEM_768.getAlgFamilyName().equals(alg.getAlgFamilyName());
        }
    }

    public static final class MlKemKeyFactory512 extends MlKemKeyFactory {
        public MlKemKeyFactory512() {
            super(Algorithm.ML_KEM_512);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_KEM_512 == alg;
        }
    }

    public static final class MlKemKeyFactory768 extends MlKemKeyFactory {
        public MlKemKeyFactory768() {
            super(Algorithm.ML_KEM_768);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_KEM_768 == alg;
        }
    }

    public static final class MLKemKeyFactory1024 extends MlKemKeyFactory {
        public MLKemKeyFactory1024() {
            super(Algorithm.ML_KEM_1024);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_KEM_1024 == alg;
        }
    }

    public static sealed class MlDsaKeyFactory extends MlKeyFactory
            permits MlDsaKeyFactory44, MlDsaKeyFactory65, MlDsaKeyFactory87 {
        public MlDsaKeyFactory() {
            super(null);
        }

        MlDsaKeyFactory(Algorithm algBound) {
            super(algBound);
        }

        @Override
        JceMlDsaPrivateKey createPrivateKey(Algorithm alg, Pkey pkey) throws InvalidKeyException {
            return new JceMlDsaPrivateKey(alg.getAlgName(), pkey);
        }

        @Override
        JceMlDsaPublicKey createPublicKey(Algorithm alg, Pkey pkey, byte[] pubDer) throws InvalidKeyException {
            return new JceMlDsaPublicKey(alg.getAlgName(), pkey, pubDer);
        }

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (key instanceof JceMlDsaPrivateKey || key instanceof JceMlDsaPublicKey) {
                if (this.isGeneric) {
                    return key;
                } else {
                    // check if right factory is used.
                    String variant = ((JceMlKey) key).variant();
                    if (variant.equals(this.alg.getAlgName())) {
                        return key;
                    } else {
                        throw new InvalidKeyException("Use correct Key Factory type");
                    }
                }
            } else if (key instanceof PrivateKey prvK) {
                return translatePrivate(prvK);
            } else if (key instanceof PublicKey pubK) {
                return translatePublic(pubK);
            } else {
                throw new InvalidKeyException("Could not translate ML-DSA Key");
            }
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_DSA_65.getAlgFamilyName().equals(alg.getAlgFamilyName());
        }
    }

    public static final class MlDsaKeyFactory44 extends MlDsaKeyFactory {
        public MlDsaKeyFactory44() {
            super(Algorithm.ML_DSA_44);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_DSA_44 == alg;
        }

    }

    public static final class MlDsaKeyFactory65 extends MlDsaKeyFactory {
        public MlDsaKeyFactory65() {
            super(Algorithm.ML_DSA_65);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_DSA_65 == alg;
        }

    }

    public static final class MlDsaKeyFactory87 extends MlDsaKeyFactory {
        public MlDsaKeyFactory87() {
            super(Algorithm.ML_DSA_87);
        }

        @Override
        boolean isSupportedAlgorithm(Algorithm alg) {
            return Algorithm.ML_DSA_87 == alg;
        }
    }

    // Wrapper class for non exported sun.security.util.RawKeySpec
    private static class RawKeySpec {
        private static final String WRAPPED_CLASS_NAME = "sun.security.util.RawKeySpec";
        private static final Method GET_KEY_ARR_METHOD;
        static {
            Method cachedMethod = null;
            try {
                Class<?> rksClazz = Class.forName(WRAPPED_CLASS_NAME);
                cachedMethod = rksClazz.getMethod("getKeyArr");
            } catch (ReflectiveOperationException e) {
                DEBUG.println("Class " + WRAPPED_CLASS_NAME + " not accessible. Use --add-exports for sun.security.util package from java.base");
            }
            GET_KEY_ARR_METHOD = cachedMethod;
        }

        private static byte[] getKeyArr(KeySpec keySpec) {
            if (GET_KEY_ARR_METHOD == null || keySpec == null || !keySpec.getClass().getName().equals(WRAPPED_CLASS_NAME)) {
                return null;
            }
            byte[] rawBytes = null;
            try {
                rawBytes = (byte[])GET_KEY_ARR_METHOD.invoke(keySpec);
            } catch (ReflectiveOperationException e) {
                DEBUG.println("Exception in reading bytes " + e.getMessage());
            }
            return rawBytes;
        }
    }
}
