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

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceOsslKey;
import com.oracle.jipher.internal.key.JceRsaPrivateKey;
import com.oracle.jipher.internal.key.JceRsaPublicKey;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.openssl.PkeyCtx;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Base {@link CipherSpi} implementation for RSA based encryption and decryption
 * operations used by the Jipher provider. It supports public-key
 * encryption / wrapping and private-key decryption / unwrapping.
 */
public abstract class RsaCipher extends CipherSpi {

    private final RsaKeyFactory kf = new RsaKeyFactory();

    private final RsaCipherPadding padding;

    private Pkey pkey;
    private boolean encrypt;

    private int keyBits;

    private byte[] buffer;
    private int bufOffset;

    RsaCipher(RsaCipherPadding padding) {
        this.padding = padding;
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        if (!this.padding.name().equals(s.toUpperCase())) {
            throw new NoSuchPaddingException();
        }
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        if (!"ECB".equals(s)) {
            throw new NoSuchAlgorithmException();
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected void engineInit(int cipherMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            engineInit(cipherMode, key, (AlgorithmParameterSpec) null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(cipherMode, key, toParamSpec(algorithmParameters), secureRandom);
    }

    AlgorithmParameterSpec toParamSpec(AlgorithmParameters params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not expected.");
        }
        return null;
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        initInternal(key, algorithmParameterSpec, cipherMode == Cipher.ENCRYPT_MODE || cipherMode == Cipher.WRAP_MODE);
    }

    void verifyParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not expected. " + params);
        }
    }

    private void initInternal(Key key, AlgorithmParameterSpec params, boolean encrypt) throws InvalidKeyException, InvalidAlgorithmParameterException {
        JceOsslKey translatedKey;
        int keyBits;
        try {
            if (encrypt) {
                if (!(key instanceof PublicKey)) {
                    throw new InvalidKeyException("Expected PublicKey for encryption");
                }
                translatedKey = (JceOsslKey) this.kf.engineTranslateKey(key);
                Fips.enforcement().checkStrength(CryptoOp.ENCRYPT_ASYM, translatedKey);
                keyBits = ((JceRsaPublicKey) translatedKey).getModulus().bitLength();
            } else {
                if (!(key instanceof PrivateKey)) {
                    throw new InvalidKeyException("Expected PrivateKey for decryption");
                }
                translatedKey = (JceOsslKey) this.kf.engineTranslateKey(key);
                Fips.enforcement().checkStrength(CryptoOp.DECRYPT_ASYM, translatedKey);
                keyBits = ((JceRsaPrivateKey) translatedKey).getModulus().bitLength();
            }
            verifyParams(params);

            // If the translatedKey is a reference to the original key (i.e. no key translation took place)
            // then create a native reference to the original PKEY so that, for private keys the cipher object
            // will be independent of the original key (which the application might destroy) and, so that
            // doInit can always free the previously latched pkey (if any).
            doInit(translatedKey == key ? Pkey.createReference(translatedKey.getPkey()) : translatedKey.getPkey(), keyBits, encrypt);
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private void doInit(Pkey pkey, int keyBits, boolean encrypt) {
        cleanup();
        if (this.pkey != null && this.pkey != pkey) {
            // Free the underlying EVP_PKEY now rather than wait for GC to do so eventually.
            // If the EVP_PKEY was created by key translation then it will be freed otherwise
            // if the EVP_PKEY was created by creating a reference the reference count will be decremented.
            this.pkey.free();
        }
        this.pkey = pkey;
        this.keyBits = keyBits;
        this.buffer = new byte[this.keyBits/8];
        this.bufOffset = 0;
        this.encrypt = encrypt;
    }

    @Override
    protected int engineUpdate(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws ShortBufferException {
        return super.engineUpdate(byteBuffer, byteBuffer1);
    }


    @Override
    protected int engineUpdate(byte[] input, int inOffset, int len, byte[] out, int outOffset) {
        engineUpdate(input, inOffset, len);
        return 0;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inOffset, int len) {
        resetIfNecessary();
        if (len != 0) {
            if (len + this.bufOffset > this.buffer.length) {
                this.bufOffset = buffer.length + 1; // Set it to one more than buffer length as an indicator.
            } else {
                System.arraycopy(input, inOffset, this.buffer, this.bufOffset, len);
                this.bufOffset += len;
            }
        }
        return null;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int offset, int len) throws IllegalBlockSizeException, BadPaddingException {
        byte[] out = new byte[engineGetOutputSize(len)];
        try {
            int outLen = engineDoFinal(input, offset, len, out, 0);
            if (outLen == out.length) {
                byte[] tmp = out;
                out = null;
                return tmp;
            }
            return Arrays.copyOf(out, outLen);
        } catch (ShortBufferException e) {
            // Should not happen
            throw new AssertionError("Internal error: Unexpected ShortBufferException", e);
        } finally {
            clearArray(out);
        }
    }

    void initPkeyCtx(PkeyCtx.Cipher ctx) {
        ctx.init(this.encrypt);
        ctx.setPadding(this.padding.id());
    }

    int cipherOperation(PkeyCtx.Cipher ctx, byte[] output, int outOffset) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        if (this.bufOffset > this.buffer.length) {
            throw new IllegalBlockSizeException("Data must not be longer than " + this.buffer.length + " bytes");
        }
        if (this.encrypt) {
            return ctx.encrypt(this.buffer, 0, this.bufOffset, output, outOffset);
        }
        return ctx.decrypt(this.buffer, 0, this.bufOffset, output, outOffset);
    }

    @Override
    protected int engineDoFinal(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return super.engineDoFinal(byteBuffer, byteBuffer1);
    }

    @Override
    protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        resetIfNecessary();
        if (this.keyBits/8 > output.length - outOffset) {
            throw new ShortBufferException();
        }
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            PkeyCtx.Cipher ctx = new PkeyCtx.Cipher(this.pkey, confinedArena);
            engineUpdate(input, offset, len);
            initPkeyCtx(ctx);
            return cipherOperation(ctx, output, outOffset);
        } finally {
            cleanup();
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return this.keyBits / 8;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected byte[] engineWrap(Key key) throws InvalidKeyException,
            IllegalBlockSizeException {
        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }
        if (encoded.length > buffer.length) {
            throw new InvalidKeyException("Key is too long for wrapping");
        }
        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            // Should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String keyAlg, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] keyBytes = null;
        if (wrappedKey.length > buffer.length) {
            throw new InvalidKeyException("Key is too long for unwrapping");
        }
        try {
            keyBytes = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return WrapUtil.createKey(keyAlg, wrappedKeyType, keyBytes);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            // Should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        } finally {
            clearArray(keyBytes);
        }
    }

    @Override
    protected int engineGetKeySize(Key key) {
        return this.keyBits;
    }

    private void cleanup() {
        if (this.buffer != null) {
            Arrays.fill(buffer, (byte) 0);
            buffer = null;
            bufOffset = 0;
        }
    }

    private void resetIfNecessary() {
        if (this.buffer == null) {
            doInit(this.pkey, this.keyBits, this.encrypt);
        }
    }

    /**
     * RSA OAEP implementation of {@link RsaCipher}. Handles the OAEP padding
     * scheme and its associated parameters (digest algorithm, MGF1 algorithm
     * and PSource). The class can be instantiated with a specific default
     * digest algorithm; when {@code hasFixedMd} is {@code true} the digest is
     * locked to that algorithm and any {@link OAEPParameterSpec} supplied must
     * match it.
     */
    public static class RsaOaep extends RsaCipher {

        final boolean hasFixedMd;
        final MdAlg defaultMdAlg;
        OAEPParameterSpec paramSpec;

        private RsaOaep(MdAlg mdAlg, boolean fixed) {
            super(RsaCipherPadding.OAEP);
            hasFixedMd = fixed;
            defaultMdAlg = mdAlg;
            paramSpec = getDefaultParameterSpec();
        }

        RsaOaep(MdAlg mdAlg) {
            this(mdAlg, true);
        }

        public RsaOaep() {
            this(MdAlg.SHA1, false);
        }

        OAEPParameterSpec getDefaultParameterSpec() {
            return new OAEPParameterSpec(defaultMdAlg.getAlg(), "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        }

        @Override
        void initPkeyCtx(PkeyCtx.Cipher ctx) {
            super.initPkeyCtx(ctx);
            MdAlg md = MdAlg.byName(this.paramSpec.getDigestAlgorithm());
            MdAlg mgf1Md = MdAlg.byName(((MGF1ParameterSpec) this.paramSpec.getMGFParameters()).getDigestAlgorithm());
            byte[] pSource = ((PSource.PSpecified) this.paramSpec.getPSource()).getValue();
            ctx.setOaepParams(md, mgf1Md, pSource);
        }

        @Override
        void verifyParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            if (params == null) {
                this.paramSpec = getDefaultParameterSpec();
            } else {
                if (!(params instanceof OAEPParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Parameter spec not supported.");
                }

                String algName = ((OAEPParameterSpec) params).getDigestAlgorithm();
                MdAlg mdAlg = MdAlg.byName(algName);
                if (mdAlg == null) {
                    throw new InvalidAlgorithmParameterException("Unsupported Digest algorithm " + algName);
                }
                if (this.hasFixedMd) {
                    if (mdAlg != this.defaultMdAlg) {
                        throw new InvalidAlgorithmParameterException(("Digest algorithm in parameter spec does not match digest algorithm in cipher transform string."));
                    }
                }

                if (!((OAEPParameterSpec) params).getMGFAlgorithm().equals("MGF1")) {
                    throw new InvalidAlgorithmParameterException("Only MGF1 supported.");
                }

                AlgorithmParameterSpec mgfSpec = ((OAEPParameterSpec) params).getMGFParameters();
                if (!(mgfSpec instanceof MGF1ParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Only MGF1ParameterSpec supported.");
                }

                algName = ((MGF1ParameterSpec) mgfSpec).getDigestAlgorithm();
                mdAlg = MdAlg.byName(algName);
                if (mdAlg == null) {
                    throw new InvalidAlgorithmParameterException("Unsupported MGF1 digest algorithm " + algName);
                }

                if (!(((OAEPParameterSpec) params).getPSource() instanceof PSource.PSpecified)) {
                    throw new InvalidAlgorithmParameterException("Unsupported PSource, must be PSource.Specified");
                }

                this.paramSpec = (OAEPParameterSpec) params;
            }
        }

        @Override
        AlgorithmParameterSpec toParamSpec(AlgorithmParameters params) throws InvalidAlgorithmParameterException {
            if (params == null) {
                return null;
            }
            if (!params.getAlgorithm().equals("OAEP")) {
                throw new InvalidAlgorithmParameterException("Invalid parameters, expected OAEP.");
            }
            try {
                return params.getParameterSpec(OAEPParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException(e);
            }
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            if (this.paramSpec != null) {
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP", InternalProvider.get());
                    params.init(this.paramSpec);
                    return params;
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("Cannot find OAEP AlgorithmParameters implementation in JipherJCE provider");
                } catch (InvalidParameterSpecException e) {
                    throw new RuntimeException("OAEPParameterSpec not supported");
                }
            } else {
                return null;
            }
        }
    }

    /**
     * RSA OAEP with SHA-1 digest (default for OAEP when no parameters are
     * supplied).
     */
    public static class RsaOaepSha1 extends RsaOaep {
        public RsaOaepSha1() {
            super(MdAlg.SHA1);
        }
    }

    /**
     * RSA OAEP with SHA-224 digest.
     */
    public static class RsaOaepSha224 extends RsaOaep {
        public RsaOaepSha224() {
            super(MdAlg.SHA224);
        }
    }

    /**
     * RSA OAEP with SHA-256 digest.
     */
    public static class RsaOaepSha256 extends RsaOaep {
        public RsaOaepSha256() {
            super(MdAlg.SHA256);
        }
    }

    /**
     * RSA OAEP with SHA-384 digest.
     */
    public static class RsaOaepSha384 extends RsaOaep {
        public RsaOaepSha384() {
            super(MdAlg.SHA384);
        }
    }

    /**
     * RSA OAEP with SHA-512 digest.
     */
    public static class RsaOaepSha512 extends RsaOaep {
        public RsaOaepSha512() {
            super(MdAlg.SHA512);
        }
    }
}
