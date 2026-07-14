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

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceOsslKey;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.MdCtx;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.fips.CryptoOp.SIGN;
import static com.oracle.jipher.internal.fips.CryptoOp.VERIFY;

/**
 * Parent class for {@link SignatureSpi} implementations where the
 * signature involves digesting the message.
 */
abstract class DigestSignature extends SignatureSpi {

    MdAlg md;
    MdCtx.Signature ctx;
    boolean isInitialized;
    protected boolean initializedForSign;
    Pkey lastPkey; // Keep track for subsequent operations without explicit init.
    protected final AsymKeyFactory kf;

    DigestSignature(MdAlg md) {
        this.md = md;
        this.kf = getKeyFactory();
    }

    abstract AsymKeyFactory getKeyFactory();

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        try {
            Fips.enforcement().checkKeyType(SIGN, privateKey.getAlgorithm());
            Fips.enforcement().checkAlg(SIGN, this.md == null ? null : md.getAlg());
            JceOsslKey prv = (JceOsslKey) kf.engineTranslateKey(privateKey);
            Fips.enforcement().checkStrength(SIGN, prv);
            // If priv is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that this service object
            // will be independent of the original key (which the application might destroy)
            doInit(prv == privateKey ? Pkey.createReference(prv.getPkey()) : prv.getPkey(), true);
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            Fips.enforcement().checkKeyType(VERIFY, publicKey.getAlgorithm());
            Fips.enforcement().checkAlg(VERIFY, this.md == null ? null : md.getAlg());
            JceOsslKey pub = (JceOsslKey) kf.engineTranslateKey(publicKey);
            Fips.enforcement().checkStrength(VERIFY, pub);
            // If pub is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that the doInit code can always
            // free the 'lastPkey' because it is not a key held by the application.
            doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey(), false);
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    void doInit(Pkey pkey, boolean isSign) throws InvalidKeyException {
        doInit(pkey, isSign, null);
    }

    void doInit(Pkey pkey, boolean isSign, MdCtx.Signature.Params params) throws InvalidKeyException {
        if (this.ctx == null) {
            this.ctx = new MdCtx.Signature();
        }
        if (isSign) {
            this.ctx.signInit(this.md, pkey, params);
        } else {
            this.ctx.verifyInit(this.md, pkey, params);
        }
        if (this.lastPkey != null && this.lastPkey != pkey) {
            // Free the EVP_PKEY now rather than wait for GC to do so eventually.
            // If the EVP_PKEY was created by key translation then it will be freed otherwise
            // if the EVP_PKEY was created by creating a reference the reference count will be decremented.
            this.lastPkey.free();
        }
        this.lastPkey = pkey;
        this.isInitialized = true;
        this.initializedForSign = isSign;
    }

    private void releaseCtx() {
        MdCtx.Signature ctxToRelease = this.ctx;
        if (ctxToRelease != null) {
            this.ctx = null;
            ctxToRelease.release();
        }
    }

    private void initIfRequired() throws SignatureException {
        if (this.isInitialized && this.ctx == null) {
            // Need to create new digest object using previous key.
            try {
                doInit(this.lastPkey, this.initializedForSign);
            } catch (InvalidKeyException e) {
                throw new SignatureException(e);
            }
        }
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) throws SignatureException {
        initIfRequired();
        if (this.initializedForSign) {
            this.ctx.signUpdate(data, off, len);
        } else {
            this.ctx.verifyUpdate(data, off, len);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    public byte[] engineSign() throws SignatureException {
        initIfRequired();
        try {
            return this.ctx.signFinal();
        } finally {
            releaseCtx();
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

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int len) throws SignatureException {
        initIfRequired();
        // Rely on Signature to check that object initialized for verify.
        try {
            if (len == 0) {
                throw new SignatureException("Signature must not be zero length");
            }
            return this.ctx.verifyFinal(sigBytes, offset, len);
        } finally {
            releaseCtx();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }
}
