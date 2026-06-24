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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.key.JceMlKey;
import com.oracle.jipher.internal.key.JceMlPrivateKey.JceMlKemPrivateKey;
import com.oracle.jipher.internal.key.JceMlPublicKey.JceMlKemPublicKey;
import com.oracle.jipher.internal.openssl.OpenSslException;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.openssl.PkeyCtx;
import com.oracle.jipher.internal.spi.MlKeyFactory.MlKemKeyFactory;

public sealed class Kem implements KEMSpi
        permits Kem.Kem512, Kem.Kem768, Kem.Kem1024 {

    private final MlKemKeyFactory keyFactory;
    private final boolean isGeneric;

    public Kem() {
        keyFactory = new MlKeyFactory.MlKemKeyFactory();
        isGeneric = true;
    }

    Kem(MlKeyFactory.MlKemKeyFactory keyFactory) {
        this.keyFactory = keyFactory;
        isGeneric = false;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
            SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException {

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("No algorithm params supported for encapsulation");
        }

        if (publicKey == null) {
            throw new InvalidKeyException("Null key");
        }

        JceMlKemPublicKey jipherPubKey;
        if (publicKey instanceof JceMlKemPublicKey) {
            jipherPubKey = (JceMlKemPublicKey) publicKey;
            // Check if KEM was instantiated to process key variant.
            if (!isGeneric) {
                String keyFactoryAlgName = keyFactory.alg.getAlgName();
                String publicKeyAlgName = jipherPubKey.variant();
                if (!keyFactoryAlgName.equals(publicKeyAlgName)) {
                    throw new InvalidKeyException("Incorrect KEM type " + keyFactoryAlgName + " for " + publicKeyAlgName);
                }
            }
        } else {
            jipherPubKey = (JceMlKemPublicKey) (keyFactory.translatePublic(publicKey));
        }

        return new EncapsulatorImpl(jipherPubKey);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("No algorithm params supported for encapsulation");
        }

        if (privateKey == null) {
            throw new InvalidKeyException("Null key");
        }

        JceMlKemPrivateKey jipherPrvKey;
        if (privateKey instanceof JceMlKemPrivateKey) {
            jipherPrvKey = (JceMlKemPrivateKey) privateKey;
            // Check if KEM was instantiated to process key variant.
            if (!isGeneric) {
                String keyFactoryAlgName = keyFactory.alg.getAlgName();
                String privateKeyAlgName = jipherPrvKey.variant();
                if (!keyFactoryAlgName.equals(privateKeyAlgName)) {
                    throw new InvalidKeyException("Incorrect KEM type " + keyFactoryAlgName + " for " + privateKeyAlgName);
                }
            }
        } else {
            jipherPrvKey = (JceMlKemPrivateKey) (keyFactory.translatePrivate(privateKey));
        }
        return new DecapsulatorImpl(jipherPrvKey);

    }

    private static class EncapsulatorImpl implements EncapsulatorSpi {

        private final Pkey publicKey;
        private final int encapSize;

        private EncapsulatorImpl(JceMlKemPublicKey publicKey) {
            assert publicKey.getPkey() != null;
            this.publicKey = publicKey.getPkey();
            this.encapSize = getEncapSize(publicKey.variant());
        }

        @Override
        public Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            Objects.requireNonNull(algorithm);
            if (from < 0) {
                throw new IndexOutOfBoundsException("from is negative");
            }
            if (from > to) {
                throw new IndexOutOfBoundsException("from is greater than to");
            }
            if (to > engineSecretSize()) {
                throw new IndexOutOfBoundsException("to is greater than secretSize");
            }
            if (from != 0 || to != engineSecretSize()) {
                throw new UnsupportedOperationException("combination of from and to is not supported");
            }

            byte[] encapsulation = null;
            byte[] secret = null;

            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                PkeyCtx.EncapsulatorDecapsulator encapImpl = new PkeyCtx.EncapsulatorDecapsulator(publicKey,
                        confinedArena);
                byte[][] secretWithEncapsulation = encapImpl.encap();
                encapsulation = secretWithEncapsulation[0];
                secret = secretWithEncapsulation[1];

                if (encapsulation.length != engineEncapsulationSize() || secret.length != engineSecretSize()) {
                    throw new AssertionError("Invalid Encapsulated Secret/Raw Secret from OpenSSL");
                }

                SecretKeySpec secretKeySpec = new SecretKeySpec(secret, 0, secret.length, algorithm);
                return new Encapsulated(secretKeySpec, encapsulation, null);
            } finally {
                // SecretKeySpec clones the incoming bytes. Clear our copy.
                Util.clearArray(secret);
            }
        }

        @Override
        public int engineSecretSize() {
            return 32;
        }

        @Override
        public int engineEncapsulationSize() {
            return encapSize;
        }
    }

    private static class DecapsulatorImpl implements DecapsulatorSpi {

        private final Pkey privateKey;
        private final int encapSize;

        private DecapsulatorImpl(JceMlKemPrivateKey privateKey) {
            assert privateKey.getPkey() != null;
            this.privateKey = privateKey.getPkey();
            this.encapSize = getEncapSize(privateKey.variant());
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            Objects.requireNonNull(encapsulation);
            Objects.requireNonNull(algorithm);
            if (from < 0) {
                throw new IndexOutOfBoundsException("from is negative");
            }
            if (from > to) {
                throw new IndexOutOfBoundsException("from is greater than to");
            }
            if (to > engineSecretSize()) {
                throw new IndexOutOfBoundsException("to is greater than secretSize");
            }
            if (from != 0 || to != engineSecretSize()) {
                throw new UnsupportedOperationException("combination of from and to is not supported");
            }

            byte[] unwrapped = null;

            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                PkeyCtx.EncapsulatorDecapsulator decapImpl = new PkeyCtx.EncapsulatorDecapsulator(privateKey,
                        confinedArena);
                unwrapped = decapImpl.decap(encapsulation);
                return new SecretKeySpec(unwrapped, from, to, algorithm);
            } catch (UnsupportedOperationException | IllegalStateException | OpenSslException | AssertionError e) {
                throw new DecapsulateException("Decapsulation failed", e);
            } finally {
                Util.clearArray(unwrapped);
            }
        }

        @Override
        public int engineSecretSize() {
            return 32;
        }

        @Override
        public int engineEncapsulationSize() {
            return encapSize;
        }
    }

    /*
     * See FIPS 203 Section 8 Table 3.
     */
    private static int getEncapSize(String mlKemAlgo) {
        return switch (mlKemAlgo) {
            case JceMlKey.STR_ML_KEM_1024 -> 1568;
            case JceMlKey.STR_ML_KEM_512 -> 768;
            default -> 1088;
        };
    }

    public static final class Kem512 extends Kem {
        public Kem512() {
            super(new MlKeyFactory.MlKemKeyFactory512());
        }
    }

    public static final class Kem768 extends Kem {
        public Kem768() {
            super(new MlKeyFactory.MlKemKeyFactory768());
        }
    }

    public static final class Kem1024 extends Kem {
        public Kem1024() {
            super(new MlKeyFactory.MLKemKeyFactory1024());
        }
    }
}
