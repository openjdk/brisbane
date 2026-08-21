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
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;

import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceOsslKey;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.fips.CryptoOp.VERIFY;

/**
 * Abstract implementation for RSA signatures (PKCS #1).
 */
public abstract class RsaDigestSig extends DigestSignature {

    RsaDigestSig(MdAlg md) {
        super(md);
    }

    private int expectedLen;

    AsymKeyFactory getKeyFactory() {
        return new RsaKeyFactory();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            Fips.enforcement().checkAlg(VERIFY, this.md == null ? null : md.getAlg());
            JceOsslKey pub = (JceOsslKey) kf.engineTranslateKey(publicKey);
            Fips.enforcement().checkStrength(VERIFY, pub);
            expectedLen = (((RSAKey) pub).getModulus().bitLength() + 7) >> 3;
            // If pub is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that the doInit code can always
            // free the 'lastPkey' because it is not a key held by the application.
            doInit(pub == publicKey ? Pkey.createReference(pub.getPkey()) : pub.getPkey(), false);
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int len) throws SignatureException {
        boolean verified = super.engineVerify(sigBytes, offset, len);
        // OpenSSL treats an octet string that does not have the expected octet length of a signature to be a signature
        // that fails verification. The JDK providers do not consider an octet string that does not have the expected
        // signature octet length to be a valid signature. If directed to perform signature verification on
        // such an octet string the JDK providers throw a SignatureException
        if (len != expectedLen) {
            throw new SignatureException("Signature length not correct: got " + len + " but was expecting " +
                    expectedLen);
        }
        return verified;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    /**
     * SHA1 with RSA implementation.
     */
    public static final class Sha1WithRsa extends RsaDigestSig {
        public Sha1WithRsa() {
            super(MdAlg.SHA1);
        }
    }

    /**
     * SHA224 with RSA implementation.
     */
    public static final class Sha224WithRsa extends RsaDigestSig {
        public Sha224WithRsa() {
            super(MdAlg.SHA224);
        }
    }

    /**
     * SHA256 with RSA implementation.
     */
    public static final class Sha256WithRsa extends RsaDigestSig {
        public Sha256WithRsa() {
            super(MdAlg.SHA256);
        }
    }

    /**
     * SHA384 with RSA implementation.
     */
    public static final class Sha384WithRsa extends RsaDigestSig {
        public Sha384WithRsa() {
            super(MdAlg.SHA384);
        }
    }

    /**
     * SHA512 with RSA implementation.
     */
    public static final class Sha512WithRsa extends RsaDigestSig {
        public Sha512WithRsa() {
            super(MdAlg.SHA512);
        }
    }
}
