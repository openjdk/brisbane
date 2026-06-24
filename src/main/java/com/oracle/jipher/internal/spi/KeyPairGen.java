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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceDhPrivateKey;
import com.oracle.jipher.internal.key.JceDhPublicKey;
import com.oracle.jipher.internal.key.JceEcPrivateKey;
import com.oracle.jipher.internal.key.JceEcPublicKey;
import com.oracle.jipher.internal.key.JceMlPrivateKey;
import com.oracle.jipher.internal.key.JceMlPublicKey;
import com.oracle.jipher.internal.key.JceRsaPrivateKey;
import com.oracle.jipher.internal.key.JceRsaPublicKey;
import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.EcCurve;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.openssl.PkeyCtx;

import static com.oracle.jipher.internal.common.InputChecks.isNullOrZeroOrNegative;


/**
 * Parent class for {@link KeyPairGenerator} algorithm implementations.
 * <p>
 * Note that KeyPairGen extends {@link KeyPairGenerator} rather than {@link java.security.KeyPairGeneratorSpi}
 * because this avoids fallback to other providers during delayed provider selection when initialize fails.
 */
public abstract class KeyPairGen extends KeyPairGenerator {

    KeyPairGen(String alg) {
        super(alg);
    }

    /**
     * Create a KeyGen object for this algorithm impl.
     * @return the KeyGen object
     */
    abstract PkeyCtx.KeyGen createKeyGen(OsslArena arena);

    /**
     * Create a new public key for the specified Pkey public key.
     * @param pub the {@link Pkey} public key
     * @return a new PublicKey object, backed by {@link Pkey}
     * @throws InvalidKeyException an error occurred creating key object
     */
    abstract PublicKey createPublicKey(Pkey pub) throws InvalidKeyException;

    /**
     * Create a new private key for the specified Pkey private key.
     * @param priv the {@link Pkey} private key
     * @return a new PrivateKey object, backed by {@link Pkey}
     * @throws InvalidKeyException an error occurred creating key object
     */
    abstract PrivateKey createPrivateKey(Pkey priv) throws InvalidKeyException;

    @Override
    public KeyPair generateKeyPair() {
        Pkey[] privPubKp = null;
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            PkeyCtx.KeyGen ctx = createKeyGen(confinedArena);
            privPubKp = ctx.generate();
            KeyPair kp = new KeyPair(createPublicKey(privPubKp[1]), createPrivateKey(privPubKp[0]));
            privPubKp = null; // Don't free privPubKp in finally block
            return kp;
        } catch (InvalidKeyException e) {
            throw new ProviderException("Failed to generate key pair", e);
        } finally {
            Pkey.free(privPubKp);
        }
    }

    /*
     * Align with JCE's behavior of using InvalidParameterException to flag
     * key size compliance issues.
     */
    protected void validate(String algo, int... keySize) {
        try {
            Fips.enforcement().checkStrength(CryptoOp.KEYGEN, algo, keySize);
        } catch (FIPSPolicyException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    /**
     * RSA {@link KeyPairGenerator} implementation.
     */
    public static final class Rsa extends KeyPairGen {
        private int modulusSize;
        private BigInteger pubExp;

        public Rsa() {
            super("RSA");
            this.modulusSize = KeySizeConfiguration.getRSAKeySize();
        }

        @Override
        PkeyCtx.KeyGen createKeyGen(OsslArena arena) {
            PkeyCtx.RsaKeyGen ctx = new PkeyCtx.RsaKeyGen(arena);
            ctx.setParams(this.modulusSize, this.pubExp);
            return ctx;
        }

        @Override
        PublicKey createPublicKey(Pkey pub) throws InvalidKeyException {
            return new JceRsaPublicKey(pub, null);
        }

        @Override
        PrivateKey createPrivateKey(Pkey priv)  {
            return new JceRsaPrivateKey(priv);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            if (keysize <= 0) {
                throw new InvalidParameterException("invalid key size");
            }
            validate("RSA", keysize);
            this.modulusSize = keysize;
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params == null) {
                throw new InvalidAlgorithmParameterException();
            }
            if (!(params instanceof RSAKeyGenParameterSpec kgParams)) {
                throw new InvalidAlgorithmParameterException();
            }
            if (kgParams.getKeysize() <= 0) {
                throw new InvalidAlgorithmParameterException("invalid key size");
            }
            if (kgParams.getPublicExponent() != null) {
                BigInteger publicExponent = kgParams.getPublicExponent();

                // FIPS 186-5 The exponent e shall be an odd positive integer such that 2^16 < e < 2^256
                // Note: 2^16 is even so we don't need to worry about 2^16 having 17 bits.
                if (publicExponent.signum() <= 0 || !publicExponent.testBit(0) ||
                        publicExponent.bitLength() <= 16 || publicExponent.bitLength() >= 257) {
                    throw new InvalidAlgorithmParameterException("Public exponent e must be an odd positive integer such that 2^16 < e < 2^256");
                }

                // If OpenSSL is directed to generate an RSA key pair using a modules with more than
                // OPENSSL_RSA_SMALL_MODULUS_BITS and a public exponent with more than
                // OPENSSL_RSA_MAX_PUBEXP_BITS it will fail the pair-wise consistency test resulting in the
                // FIPS module entering an error state. We want to avoid this because the only way to clear
                // the FIPS module error state is to unload and reload the FIPS module.
                if (kgParams.getKeysize() > EVP_PKEY.RSA_SMALL_MODULUS_BITS &&
                        publicExponent.bitLength() > EVP_PKEY.RSA_MAX_PUBEXP_BITS) {
                    throw new InvalidAlgorithmParameterException(String.format(
                            "Generating an RSA key with a length of more than %d bits and a public key exponent " +
                            "of more than %d bits is not supported.",
                            EVP_PKEY.RSA_SMALL_MODULUS_BITS, EVP_PKEY.RSA_MAX_PUBEXP_BITS));
                }
            }
            validate("RSA", kgParams.getKeysize());
            this.modulusSize = kgParams.getKeysize();
            this.pubExp = kgParams.getPublicExponent();

        }
    }

    /**
     * EC {@link KeyPairGenerator} implementation.
     */
    public static final class Ec extends KeyPairGen {
        private EcCurve curveId;

        public Ec() {
            super("EC");

            // In case the app does not explicitly initialize, init to default.
            initialize(KeySizeConfiguration.getECKeySize(), null);
        }

        @Override
        PkeyCtx.KeyGen createKeyGen(OsslArena arena) {
            Pkey pkey = null;
            try {
                pkey = Pkey.newEcParams(this.curveId);
                return new PkeyCtx.EcKeyGen(pkey, arena);
            } finally {
                Pkey.free(pkey);
            }
        }

        @Override
        PublicKey createPublicKey(Pkey pub) throws InvalidKeyException {
            return new JceEcPublicKey(pub, null);
        }

        @Override
        PrivateKey createPrivateKey(Pkey priv) throws InvalidKeyException {
            return new JceEcPrivateKey(priv);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            validate("EC", keysize);
            this.curveId = determineCurve(keysize);

        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params == null) {
                throw new InvalidAlgorithmParameterException();
            }
            this.curveId = determineCurve(params);
            if (this.curveId == null) {
                throw new InvalidAlgorithmParameterException("curve not supported");
            }
            validate("EC", this.curveId.keyBits());
        }

        /**
         * Determine an {@link EcCurve} for a requested key size (in bits).
         * @param keySize the requested key size in bits
         * @return an {@link EcCurve}
         * @throws InvalidParameterException if no EC parameters supported for the requested key size
         */
        EcCurve determineCurve(int keySize) throws InvalidParameterException {
            return switch (keySize) {
                case 224 -> EcCurve.secp224r1;
                case 256 -> EcCurve.secp256r1;
                case 384 -> EcCurve.secp384r1;
                case 521 -> EcCurve.secp521r1;
                default ->
                        throw new InvalidParameterException("No EC parameters available for key size " + keySize + ", supported=224,256,384,521");
            };
        }

        /**
         * Determine an {@link EcCurve} that corresponds to the specified {@link AlgorithmParameterSpec}.
         * @param spec an {@link AlgorithmParameterSpec} Supported: {@link  ECGenParameterSpec}, {@link ECParameterSpec}
         * @return an {@link EcCurve}
         * @throws InvalidAlgorithmParameterException if no supported curve matches spec parameters
         */
        EcCurve determineCurve(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            if (spec instanceof ECGenParameterSpec) {
                return NamedCurves.lookup(((ECGenParameterSpec) spec));
            }
            if (spec instanceof ECParameterSpec) {
                return NamedCurves.lookup(((ECParameterSpec) spec));
            }
            throw new InvalidAlgorithmParameterException("Only ECGenParameterSpec and ECParameterSpec supported.");
        }
    }

    /**
     * DH {@link KeyPairGenerator} implementation.
     */
    public static final class Dh extends KeyPairGen {

        private DHParameterSpec dhParams;

        public Dh() {
            super("DH");
            initialize(KeySizeConfiguration.getDHKeySize());
        }

        @Override
        PkeyCtx.KeyGen createKeyGen(OsslArena arena) {
            Pkey pkey = null;
            try {
                pkey = Pkey.newDhParams(this.dhParams);
                return new PkeyCtx.DhKeyGen(pkey, arena);
            } finally {
                Pkey.free(pkey);
            }
        }

        @Override
        PrivateKey createPrivateKey(Pkey priv) throws InvalidKeyException {
            return new JceDhPrivateKey(priv);
        }

        @Override
        PublicKey createPublicKey(Pkey pub) throws InvalidKeyException {
            return new JceDhPublicKey(pub, null);
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            this.dhParams = DhParamCache.get(keysize);
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (params == null) {
                throw new InvalidAlgorithmParameterException();
            }
            if (params instanceof DHParameterSpec spec) {
                if (isNullOrZeroOrNegative(spec.getP(), spec.getG())) {
                    throw new InvalidAlgorithmParameterException("Parameter spec must not contain null, zero, or negative values");
                }
                validate("DH", spec.getP().bitLength());
                this.dhParams = spec;
            } else if (params instanceof DSAParameterSpec dsaParams) {
                // Accept DSA parameter spec to accept parameters generated using FIPS-186 DSA params
                // DSAParameterSpec allows specification of the q-value (which DH parameter spec does not
                if (isNullOrZeroOrNegative(dsaParams.getP(), dsaParams.getG(), dsaParams.getQ())) {
                    throw new InvalidAlgorithmParameterException("Parameter spec must not contain null, zero, or negative values");
                }
                validate("DSA", dsaParams.getP().bitLength(), dsaParams.getQ().bitLength());
                this.dhParams = new DHFIPSParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
            } else {
                throw new InvalidAlgorithmParameterException("Expected DHParameterSpec or DSAParameterSpec");
            }
        }
    }

    /**
     * ML-KEM KeyPairGeneratorSpi implementation.
     */
    public static sealed class MlKem extends KeyPairGen permits MlKem512, MlKem768, MlKem1024 {

        private String mlKEMAlgo;
        private final boolean isGeneric;

        public MlKem() {
            super("ML-KEM");
            this.mlKEMAlgo = PQCParameterSpecs.ML_KEM_768.getName(); //default to ML-KEM-768.
            this.isGeneric = true;
        }

        MlKem(NamedParameterSpec paramSpec) {
            super("ML-KEM");
            this.mlKEMAlgo = paramSpec.getName();
            this.isGeneric = false;
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            throw new InvalidParameterException("Use NamedParameterSpec to initialize.");
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {

            // Use defaults.
            if (params == null) {
                return;
            }
            if (!(params instanceof NamedParameterSpec)) {
               throw new InvalidAlgorithmParameterException("Unsupported Parameters of type: " + params.getClass().getName());
            }

            NamedParameterSpec namedParamSpec = (NamedParameterSpec)params;

            if (this.isGeneric) {
                // In generic construction, check if the params are from KEM family.
                if (!PQCParameterSpecs.isMLKEMSpec(namedParamSpec)) {
                    throw new InvalidAlgorithmParameterException("Unsupported NamedParameterSpec type: " + namedParamSpec.getName());
                }
                this.mlKEMAlgo = namedParamSpec.getName();
            } else {
                // If construction is specific to ML-KEM variant, check that.
                if (!this.mlKEMAlgo.equals(namedParamSpec.getName())) {
                    throw new InvalidAlgorithmParameterException("Unsupported parameter set name: " + namedParamSpec.getName());
                }
            }
        }

        @Override
        public void initialize(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            this.initialize(params, null);
        }

        @Override
        PkeyCtx.KeyGen createKeyGen(OsslArena arena) {
            PkeyCtx.KeyGen ctx = new PkeyCtx.MLKeyGen(this.mlKEMAlgo, arena);
            return ctx;
        }

        @Override
        PublicKey createPublicKey(Pkey pub) throws InvalidKeyException {
            return new JceMlPublicKey.JceMlKemPublicKey(this.mlKEMAlgo, pub);
        }

        @Override
        PrivateKey createPrivateKey(Pkey priv) throws InvalidKeyException {
            return new JceMlPrivateKey.JceMlKemPrivateKey(this.mlKEMAlgo, priv);
        }
    }

    public static final class MlKem512 extends MlKem {
        public MlKem512() {
            super(PQCParameterSpecs.ML_KEM_512);
        }
    }

    public static final class MlKem768 extends MlKem {
        public MlKem768() {
            super(PQCParameterSpecs.ML_KEM_768);
        }
    }

    public static final class MlKem1024 extends MlKem {
        public MlKem1024() {
            super(PQCParameterSpecs.ML_KEM_1024);
        }
    }

    /**
     * ML-DSA KeyPairGeneratorSpi implementation.
     */
    public static sealed class MlDsa extends KeyPairGen permits MlDsa44, MlDsa65, MlDsa87 {

        private String mlDSAAlgo;
        private final boolean isGeneric;

        public MlDsa() {
            super("ML-DSA");
            this.mlDSAAlgo = PQCParameterSpecs.ML_DSA_65.getName();
            this.isGeneric = true;
        }

        MlDsa(NamedParameterSpec paramSpec) {
            super("ML-DSA");
            this.mlDSAAlgo = paramSpec.getName();
            this.isGeneric = false;
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            throw new InvalidParameterException("Use NamedParameterSpec to initialize.");
        }

        @Override
        public void initialize(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            initialize(params, null);
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
                throws InvalidAlgorithmParameterException {

            if (params == null) {
                return;
            }
            if (!(params instanceof NamedParameterSpec)) {
               throw new InvalidAlgorithmParameterException();
            }

            NamedParameterSpec namedParamSpec = (NamedParameterSpec)params;

            if (this.isGeneric) {
                if (!PQCParameterSpecs.isMLDSASpec(namedParamSpec)) {
                    throw new InvalidAlgorithmParameterException();
                }
                this.mlDSAAlgo = namedParamSpec.getName();
            } else {
                if (!mlDSAAlgo.equals(namedParamSpec.getName())) {
                    throw new InvalidAlgorithmParameterException("Unsupported parameter set name: " + namedParamSpec.getName());
                }
            }
        }

        @Override
        PkeyCtx.KeyGen createKeyGen(OsslArena arena) {
            PkeyCtx.KeyGen ctx = new PkeyCtx.MLKeyGen(this.mlDSAAlgo, arena);
            return ctx;
        }

        @Override
        PublicKey createPublicKey(Pkey pub) throws InvalidKeyException {
            return new JceMlPublicKey.JceMlDsaPublicKey(this.mlDSAAlgo, pub);
        }

        @Override
        PrivateKey createPrivateKey(Pkey priv) throws InvalidKeyException {
            return new JceMlPrivateKey.JceMlDsaPrivateKey(this.mlDSAAlgo, priv);
        }
    }

    public static final class MlDsa44 extends MlDsa {
        public MlDsa44() {
            super(PQCParameterSpecs.ML_DSA_44);
        }
    }

    public static final class MlDsa65 extends MlDsa {
        public MlDsa65() {
            super(PQCParameterSpecs.ML_DSA_65);
        }
    }

    public static final class MlDsa87 extends MlDsa {
        public MlDsa87() {
            super(PQCParameterSpecs.ML_DSA_87);
        }
    }

}
