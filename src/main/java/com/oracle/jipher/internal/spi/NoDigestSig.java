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

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceDsaPublicKey;
import com.oracle.jipher.internal.key.JceEcPrivateKey;
import com.oracle.jipher.internal.key.JceEcPublicKey;
import com.oracle.jipher.internal.key.JceMlPrivateKey.JceMlDsaPrivateKey;
import com.oracle.jipher.internal.key.JceMlPublicKey.JceMlDsaPublicKey;
import com.oracle.jipher.internal.key.JceRsaPrivateKey;
import com.oracle.jipher.internal.key.JceRsaPublicKey;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.openssl.PkeyCtx;
import com.oracle.jipher.internal.openssl.PkeyCtx.Signature;
import com.oracle.jipher.internal.spi.MlKeyFactory.MlDsaKeyFactory;
import com.oracle.jipher.internal.spi.MlKeyFactory.MlDsaKeyFactory44;
import com.oracle.jipher.internal.spi.MlKeyFactory.MlDsaKeyFactory65;
import com.oracle.jipher.internal.spi.MlKeyFactory.MlDsaKeyFactory87;

import static com.oracle.jipher.internal.fips.CryptoOp.SIGN;
import static com.oracle.jipher.internal.fips.CryptoOp.VERIFY;


/**
 * Implementation of {@link SignatureSpi} for {@code NONEWith}
 * <a href=https://docs.oracle.com/en/java/javase/25/docs/specs/security/standard-names.html#signature-algorithms>Signature algorithms</a>
 * (e.g {@code NONEwithDSA}. {@code NONEwithRSA}, {@code NONEwithECDSA}),
 * where no digesting is done, and for {@code ML-DSA}, where all message data must be
 * buffered and then processed as a one-shot operation.
 */
public abstract class NoDigestSig extends SignatureSpi {

    private ByteArrayOutputStream tbs;
    private Pkey lastPkey; // Keep track for subsequent operations without explicit init.

    void doInit(Pkey pkey) {
        cleanup();
        if (this.lastPkey != null && this.lastPkey != pkey) {
            // Free the EVP_PKEY now rather than wait for GC to do so eventually.
            // If the EVP_PKEY was created by key translation then it will be freed otherwise
            // if the EVP_PKEY was created by creating a reference the reference count will be decremented.
            this.lastPkey.free();
        }
        this.lastPkey = pkey;
        this.tbs = new ByteArrayOutputStream();
    }

    private void cleanup() {
        this.tbs = null;
    }

    private void initIfRequired() {
        if (this.tbs == null) {
            doInit(this.lastPkey);
        }
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) {
        initIfRequired();
        this.tbs.write(data, off, len);
    }

    @Override
    protected void engineUpdate(byte b) {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    protected void signInit(PkeyCtx.Signature ctx) throws InvalidKeyException {
        ctx.signInit();
    }

    @Override
    public byte[] engineSign() throws SignatureException {
        initIfRequired();
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            PkeyCtx.Signature ctx = new PkeyCtx.Signature(this.lastPkey, confinedArena);
            byte[] bb = this.tbs.toByteArray();
            if (bb.length == 0) {
                throw new SignatureException("No input bytes.");
            }
            signInit(ctx);
            return ctx.sign(bb, 0, bb.length);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } finally {
            cleanup();
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    protected void verifyInit(PkeyCtx.Signature ctx) throws InvalidKeyException {
        ctx.verifyInit();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int len) throws SignatureException {
        initIfRequired();
        // Rely on Signature to check that object initialized for verify.
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            if (len == 0) {
                throw new SignatureException("Signature must not be zero length");
            }
            PkeyCtx.Signature ctx = new PkeyCtx.Signature(this.lastPkey, confinedArena);
            byte[] bb = this.tbs.toByteArray();
            verifyInit(ctx);
            return ctx.verify(sigBytes, offset, len, bb, 0, bb.length);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } finally {
            cleanup();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    /**
     * No digest with RSA.
     */
    public static final class NoneWithRsa extends NoDigestSig {

        private int expectedLen;

        private final RsaKeyFactory kf = new RsaKeyFactory();

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            JceRsaPrivateKey prv = (JceRsaPrivateKey) this.kf.engineTranslateKey(privateKey);
            // If priv is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that this service object
            // will be independent of the original key (which the application might destroy)
            doInit(prv == privateKey ? Pkey.createReference(prv.getPkey()) : prv.getPkey());
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            JceRsaPublicKey pub = (JceRsaPublicKey) this.kf.engineTranslateKey(publicKey);
            this.expectedLen = (pub.getModulus().bitLength() + 7) >> 3;
            // If pub is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that the doInit code can always
            // free the 'lastPkey' because it is not a key held by the application.
            doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey());
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes, int offset, int len) throws SignatureException {
            boolean verified = super.engineVerify(sigBytes, offset, len);
            // OpenSSL treats an octet string that does not have the expected octet length of a signature to be a signature
            // that fails verification. The JDK providers do not consider an octet string that does not have the expected
            // signature octet length to be a valid signature. If directed to perform signature verification on
            // such an octet string the JDK providers throw a SignatureException
            if ((len != this.expectedLen)) {
                throw new SignatureException("Signature length not correct: got " + len + " but was expecting " +
                        this.expectedLen);
            }
            return verified;
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return engineVerify(sigBytes, 0, sigBytes.length);
        }
    }

    /**
     * No digest with ECDSA.
     */
    public static final class NoneWithEcdsa extends NoDigestSig {

        private final EcKeyFactory kf = new EcKeyFactory();

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            JceEcPrivateKey prv = (JceEcPrivateKey) this.kf.engineTranslateKey(privateKey);
            // If priv is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that this service object
            // will be independent of the original key (which the application might destroy)
            doInit(prv == privateKey ? Pkey.createReference(prv.getPkey()) : prv.getPkey());
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            JceEcPublicKey pub = (JceEcPublicKey) this.kf.engineTranslateKey(publicKey);
            // If pub is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that the doInit code can always
            // free the 'lastPkey' because it is not a key held by the application.
            doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey());
        }
    }

    /**
     * No digest with DSA.
     */
    public static final class NoneWithDsa extends NoDigestSig {

        private final DsaKeyFactory kf = new DsaKeyFactory();

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            try {
                Fips.enforcement().checkKeyType(SIGN, privateKey.getAlgorithm());
                // This should only happen if FIPS enforcement is NONE
                throw new UnsupportedOperationException("DSA signature generation");
            } catch (FIPSPolicyException e) {
                throw new InvalidKeyException(e.getMessage(), e);
            }
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            try {
                Fips.enforcement().checkKeyType(VERIFY, publicKey.getAlgorithm());
                JceDsaPublicKey pub = (JceDsaPublicKey) this.kf.engineTranslateKey(publicKey);
                // If pub is a java reference to the original key (no key translation took place)
                // then create a native reference to the original PKEY so that the doInit code can always
                // free the 'lastPkey' because it is not a key held by the application.
                doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey());
            } catch (FIPSPolicyException e) {
                throw new InvalidKeyException(e.getMessage(), e);
            }
        }
    }

    /**
     * ML-DSA Signatures.
     */
    public static sealed class MLDSASig extends NoDigestSig permits MLDSASig44, MLDSASig65, MLDSASig87 {

        public MLDSASig() {
            this(new MlDsaKeyFactory());
        }

        MLDSASig(MlDsaKeyFactory kf) {
            this.kf = kf;
        }

        private final MlDsaKeyFactory kf;

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            JceMlDsaPrivateKey prv = (JceMlDsaPrivateKey) this.kf.engineTranslateKey(privateKey);
            // If priv is a java reference to the original key (no key
            // translation took place)
            // then create a native reference to the original PKEY so that this
            // service object
            // will be independent of the original key (which the application
            // might destroy)
            doInit(prv == privateKey ? Pkey.createReference(prv.getPkey()) : prv.getPkey());
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            JceMlDsaPublicKey pub = (JceMlDsaPublicKey) this.kf.engineTranslateKey(publicKey);
            // If pub is a java reference to the original key (no key
            // translation took place)
            // then create a native reference to the original PKEY so that the
            // doInit code can always
            // free the 'lastPkey' because it is not a key held by the
            // application.
            doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey());
        }

        @Override
        protected final void signInit(Signature ctx) throws InvalidKeyException {
            ctx.signMessageInit();
        }

        @Override
        protected void verifyInit(Signature ctx) throws InvalidKeyException {
            ctx.verifyMessageInit();
        }
    }

    public static final class MLDSASig44 extends MLDSASig {
        public MLDSASig44() {
            super(new MlDsaKeyFactory44());
        }
    }

    public static final class MLDSASig65 extends MLDSASig {
        public MLDSASig65() {
            super(new MlDsaKeyFactory65());
        }
    }

    public static final class MLDSASig87 extends MLDSASig {
        public MLDSASig87() {
            super(new MlDsaKeyFactory87());
        }
    }
}
