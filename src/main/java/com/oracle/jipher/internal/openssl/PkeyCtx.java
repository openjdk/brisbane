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
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.oracle.jipher.internal.common.Util;

/**
 * PkeyCtx object.
 */
public abstract class PkeyCtx {

    protected final EVP_PKEY_CTX evpPkeyCtx;

    PkeyCtx(EVP_PKEY_CTX evpPkeyCtx) {
        this.evpPkeyCtx = evpPkeyCtx;
    }

    static EVP_PKEY_CTX newEvpCtxIKE(EVP_PKEY evpPkey, OsslArena arena) throws InvalidKeyException {
        try {
            return LibCtx.newPkeyCtx(evpPkey, arena);
        } catch (OpenSslException e) {
            throw new InvalidKeyException("Failed to create OpenSSL object", e);
        }
    }

    /**
     * PkeyCtx for Key Generation.
     */
    public static abstract class KeyGen extends PkeyCtx {
        final Pkey.KeyType type;

        KeyGen(EVP_PKEY_CTX evpPkeyCtx, Pkey.KeyType type) {
            super(evpPkeyCtx);
            this.type = type;
        }

        /**
         * Initialize the key gen ctx with the algorithm-specific parameters.
         * @throws OpenSslException if an error occurred
         */
        void initParams() throws OpenSslException {
            // Nothing to do
        }

        /*
         * Generate Pkey private key.
         */
        Pkey generatePkey() {
            return new Pkey(this.type, Pkey.ContentType.KEY_PAIR, this.evpPkeyCtx::generate);
        }

        /**
         * Generate a Pkey pair with the given parameters.
         * @return an array containing the private key Pkey and the public key Pkey
         * @throws ProviderException if an error occurred during generation
         * @throws InvalidKeyException if an error occurred while creating public key from key pair
         */
        public Pkey[] generate() throws ProviderException, InvalidKeyException {
            Pkey pkey = null;
            try {
                this.evpPkeyCtx.keygenInit();
                initParams();
                pkey = generatePkey();
                Pkey[] kp = new Pkey[] {
                    pkey, pkey.createPub()
                };
                pkey = null; // Don't free pkey in finally block
                return kp;
            } catch (OpenSslException e) {
                throw new ProviderException("Failed to generate key pair", e);
            } finally {
                Pkey.free(pkey);
            }
        }
    }

    /**
     * RSA Key generation object.
     */
    public static final class RsaKeyGen extends KeyGen {

        private int bits;
        private BigInteger exp;
        public RsaKeyGen(OsslArena arena) {
            super(LibCtx.newPkeyCtx("RSA", arena), Pkey.KeyType.RSA);
        }

        /**
         * Set the key pair generation parameters.
         * @param keyBits the number of bits of RSA key size
         * @param pubExp the public exponent, as bytes, or null if default is to be assumed
         */
        public void setParams(int keyBits, BigInteger pubExp) {
            this.bits = keyBits;
            this.exp = pubExp;
        }

        @Override
        void initParams() throws OpenSslException {
            ArrayList<OSSL_PARAM> params = new ArrayList<>();
            params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_BITS, this.bits));
            if (this.exp != null) {
                params.add(OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_E, this.exp));
            }
            this.evpPkeyCtx.setParams(params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        }

        @Override
        public Pkey[] generate() throws InvalidParameterException, InvalidKeyException {
            if (this.bits == 0) {
                throw new IllegalStateException("setParams was not called.");
            }
            return super.generate();
        }
    }

    /**
     * EC Key generation object.
     */
    public static final class EcKeyGen extends KeyGen {
        public EcKeyGen(Pkey params, OsslArena arena) {
            super(LibCtx.newPkeyCtx(params.getEvpPkey(), arena), Pkey.KeyType.EC);
        }
    }

    /**
     * DH Key generation object.
     */
    public static final class DhKeyGen extends KeyGen {
        public DhKeyGen(Pkey params, OsslArena arena) {
            super(LibCtx.newPkeyCtx(params.getEvpPkey(), arena), Pkey.KeyType.DH);
        }
    }

    /*
     * Base class for ML* KeyGen.
     */
    public static final class MLKeyGen extends KeyGen {
        private final String mlAlgo;

        public MLKeyGen(String mlAlgo, OsslArena arena) {
            super(LibCtx.newPkeyCtx(mlAlgo, arena), Pkey.KeyType.ML);
            this.mlAlgo = mlAlgo;
        }

        @Override
        Pkey generatePkey() {
            return new Pkey(this.type, this.mlAlgo, Pkey.ContentType.KEY_PAIR, this.evpPkeyCtx::generate);
        }
    }

    /**
     * Derive / key agree context object.
     */
    public static final class Derive extends PkeyCtx {

        public Derive(Pkey pkey, OsslArena arena) throws InvalidKeyException {
            super(newEvpCtxIKE(pkey.getEvpPkey(), arena));
            try {
                // Configure OpenSSL's DH (FFC) key establishment to retain leading zero bytes of the shared secret as
                // defined in NIST SP 800-56A (C.1) [By default OpenSSL's DH (FFC) key establishment implementation
                // strips leading zeros as defined in RFC 5246 (8.1.2)].
                // Note: 'OSSL_EXCHANGE_PARAM_PAD' is not supported (is ignored) by OpenSSL's EC_DH (ECC) key
                // establishment implementation which never strips leading zeros from the shared secret */
                OSSL_PARAM param = OSSL_PARAM.of(EVP_PKEY.EXCHANGE_PARAM_PAD, 1);
                this.evpPkeyCtx.deriveInit(param);
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize pkey ctx for key agreement", e);
            }
        }

        public byte[] derive(Pkey peer) throws InvalidKeyException {
            try {
                this.evpPkeyCtx.deriveSetPeer(peer.getEvpPkey(), true);
            } catch (OpenSslException e) {
                // The root cause of this failure is almost certain to be either:
                //  * The public key failed validation as defined in SP.800-56Ar3 section 5.6.2.3
                //      - this could be confirmed by calling EVP_PKEY_public_check
                //  * The public key is for a different field (elliptic curve or FFC domain parameters) or to the private key
                //      - this could be confirmed by examining the OpenSSL Error code/string.
                throw new InvalidKeyException("Failed to set peer for key derivation", e);
            }

            int expectedDerivedKeyLen = this.evpPkeyCtx.derive(null, 0);
            byte[] derivedKey = new byte[expectedDerivedKeyLen];
            int derivedKeyLen = this.evpPkeyCtx.derive(derivedKey, 0);
            if (derivedKeyLen < expectedDerivedKeyLen) {
                try {
                    return Arrays.copyOf(derivedKey, derivedKeyLen);
                } finally {
                    Util.clearArray(derivedKey);
                }
            }
            return derivedKey;
        }
    }

    /**
     * Signature context object.
     */
    public static final class Signature extends PkeyCtx {
        public Signature(Pkey pkey, OsslArena arena) throws InvalidKeyException {
            super(newEvpCtxIKE(pkey.getEvpPkey(), arena));
        }

        public void signInit() throws InvalidKeyException {
            try {
                this.evpPkeyCtx.signInit();
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize pkey ctx for signing", e);
            }
        }

        public void signMessageInit() throws InvalidKeyException {
            try {
                assert (this.evpPkeyCtx.isA("ML-DSA-44") || this.evpPkeyCtx.isA("ML-DSA-65")
                        || this.evpPkeyCtx.isA("ML-DSA-87"));
                this.evpPkeyCtx.signMessageInit();
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize pkey ctx for signing", e);
            }
        }

        public void verifyInit() throws InvalidKeyException {
            try {
                this.evpPkeyCtx.verifyInit();
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize pkey ctx for verifying", e);
            }
        }

        public void verifyMessageInit() throws InvalidKeyException {
            try {
                assert (this.evpPkeyCtx.isA("ML-DSA-44") || this.evpPkeyCtx.isA("ML-DSA-65")
                        || this.evpPkeyCtx.isA("ML-DSA-87"));
                this.evpPkeyCtx.verifyMessageInit();
            } catch (OpenSslException e) {
                throw new InvalidKeyException("Failed to initialize pkey ctx for verifying", e);
            }
        }

        public byte[] sign(byte[] input, int offset, int len) throws SignatureException {
            try {
                int expectedSigLen = this.evpPkeyCtx.sign(input, offset, len, null, 0);
                byte[] sig = new byte[expectedSigLen];
                int sigLen = this.evpPkeyCtx.sign(input, offset, len, sig, 0);
                if (sigLen < expectedSigLen) {
                    return Arrays.copyOf(sig, sigLen);
                }
                return sig;
            } catch (OpenSslException e) {
                throw new SignatureException("No-digest signing operation failed", e);
            }
        }

        public boolean verify(byte[] signature, int sigOff, int sigLen, byte[] input, int off, int len) throws SignatureException{
            return this.evpPkeyCtx.verify(input, off, len, signature, sigOff, sigLen);
        }
    }

    /**
     * Asym cipher context.
     */
    public static final class Cipher extends PkeyCtx {

        public Cipher(Pkey pkey, OsslArena arena) {
            super(LibCtx.newPkeyCtx(pkey.getEvpPkey(), arena));
        }

        public void init(boolean encrypt) {
            if (encrypt) {
                this.evpPkeyCtx.encryptInit();
            } else {
                this.evpPkeyCtx.decryptInit();
            }
        }

        // paddingMode - one of the EVP_PKEY.PKEY_RSA_PAD_MODE_* strings
        public void setPadding(String paddingMode) {
            this.evpPkeyCtx.setParams(OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PAD_MODE, paddingMode));
        }

        public void setOaepParams(MdAlg md, MdAlg mgf1Md, byte[] pVal) {
                this.evpPkeyCtx.setParams(
                        OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_OAEP_DIGEST, md.getAlg()),
                        OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Md.getAlg()),
                        OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_OAEP_LABEL,  pVal));
        }

        public int encrypt(byte[] input, int offset, int len, byte[] output, int outOffset) throws IllegalBlockSizeException, ShortBufferException {
            try {
                int outLen = this.evpPkeyCtx.encrypt(input, offset, len, null, 0);
                if (outLen > output.length - outOffset) {
                    throw new ShortBufferException("Not enough space in output array");
                }
                return this.evpPkeyCtx.encrypt(input, offset, len, output, outOffset);
            } catch (OpenSslException e) {
                IllegalBlockSizeException ibse = new IllegalBlockSizeException(e.getMessage());
                ibse.initCause(e);
                throw ibse;
            }
        }

        public int decrypt(byte[] input, int offset, int len, byte[] output, int outOffset) throws BadPaddingException, ShortBufferException {
            try {
                int outLen = this.evpPkeyCtx.decrypt(input, offset, len, null, 0);
                if (outLen > output.length - outOffset) {
                    throw new ShortBufferException("Not enough space in output array");
                }
                return this.evpPkeyCtx.decrypt(input, offset, len, output, outOffset);
            } catch (OpenSslException e) {
                BadPaddingException bpe = new BadPaddingException(e.getMessage());
                bpe.initCause(e);
                throw bpe;
            }
        }
    }
    /**
     * ML-KEM Encap/Decap context.
     */
    public static final class EncapsulatorDecapsulator extends PkeyCtx {

        public EncapsulatorDecapsulator(Pkey pkey, OsslArena arena) throws ProviderException {
            super(LibCtx.newPkeyCtx(pkey.getEvpPkey(), arena));
        }

        /*
         * Returns the encapsulated key (index 0) and the secret (index 1) in
         * order.
         */
        public byte[][] encap() {
            this.evpPkeyCtx.encapsulateInit();
            int[] sizes = this.evpPkeyCtx.encapsulate(null, 0, null, 0);
            byte[] wrappedKey = new byte[sizes[0]];
            byte[] genKey = new byte[sizes[1]];
            this.evpPkeyCtx.encapsulate(wrappedKey, 0, genKey, 0);
            return new byte[][] {wrappedKey, genKey};
        }

        /*
         * Return the secret from an encapsulation.
         */
        public byte[] decap(byte[] encapsulated) {
            this.evpPkeyCtx.decapsulateInit();
            // This will be 32 for all ML-KEM variants.
            int secretKeyLen = this.evpPkeyCtx.decapsulate(encapsulated, 0, encapsulated.length, null, 0);
            byte[] secret = new byte[secretKeyLen];
            this.evpPkeyCtx.decapsulate(encapsulated, 0, encapsulated.length, secret, 0);
            return secret;
        }
    }

}
