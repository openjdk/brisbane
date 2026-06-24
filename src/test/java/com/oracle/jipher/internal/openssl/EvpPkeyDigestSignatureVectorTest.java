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

import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.SignatureTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.keyId;

/**
 * Tests
 *    EVP_DigestSignInit_ex,   EVP_DigestSignUpdate,   EVP_DigestSignFinal
 *    EVP_DigestVerifyInit_ex, EVP_DigestVerifyUpdate, EVP_DigestVerifyFinal
 *  using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpPkeyDigestSignatureVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        Predicate<Object[]> nonDigestSignature =
                param -> ((SignatureTestVector) param[1]).getAlg().toUpperCase().startsWith("NONE");
        Predicate<Object[]> mlDsaSignature =
                        param -> ((SignatureTestVector) param[1]).getAlg().toUpperCase().startsWith("ML-DSA");
        Predicate<Object[]> digestSignature = nonDigestSignature.or(mlDsaSignature).negate();
        return TestData.forParameterized(SignatureTestVector.class)
                .stream().filter(digestSignature).collect(Collectors.toList());
    }

    private Version fipsProviderVersion;

    private final String alg;
    private final KeySpec privateKeySpec;
    private final KeySpec publicKeySpec;
    private final String mdAlg;
    private final int saltLen;
    private final byte[] data;
    private final byte[] signature;

    private EVP_MD_CTX signCtx;
    private EVP_MD_CTX verifyCtx;

    static String getOpenSslMdAlg(String alg) {
        if (alg.toUpperCase().startsWith("NONE")) {
            return null;
        }
        String digest = (alg.contains("with") ? alg.substring(0, alg.indexOf("with")) : alg)
                .replace("SHA-", "SHA").replace("SHA", "SHA-");
        return switch (digest) {
            case "SHA-1" -> EVP_MD.DIGEST_NAME_SHA1;
            case "SHA-224" -> EVP_MD.DIGEST_NAME_SHA2_224;
            case "SHA-256" -> EVP_MD.DIGEST_NAME_SHA2_256;
            case "SHA-384" -> EVP_MD.DIGEST_NAME_SHA2_384;
            case "SHA-512" -> EVP_MD.DIGEST_NAME_SHA2_512;
            default -> throw new AssertionError();
        };
    }

    static boolean isRsaPss(String alg) {
        return alg.toUpperCase().contains("RSAANDMGF1") || alg.toUpperCase().contains("RSASSA-PSS");
    }

    public EvpPkeyDigestSignatureVectorTest(String description, SignatureTestVector tv) throws Exception {
        this.alg = tv.getAlg();
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        this.privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        if (tv.getParams() != null) {
            this.mdAlg =  getOpenSslMdAlg(tv.getParams().digest() == null ? this.alg : tv.getParams().digest());
            this.saltLen = tv.getParams().getSaltLen();
        } else {
            this.mdAlg = getOpenSslMdAlg(this.alg);
            this.saltLen = EVP_PKEY.PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_AUTO;
        }
        this.data = tv.getData();
        this.signature = tv.getSignature();

        Assume.assumeTrue(FipsProviderInfoUtil.isSHA1DigestSignatureSupported() || !this.mdAlg.equals(EVP_MD.DIGEST_NAME_SHA1));
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported() || !this.alg.contains("withDSA"));
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        Consumer<EVP_PKEY_CTX> params = isRsaPss(this.alg) ? new PssParams(this.saltLen) : null;

        this.signCtx = openSsl.newEvpMdCtx(testArena);
        EVP_PKEY privateKey = KeyUtil.loadPrivate(this.privateKeySpec, this.libCtx, this.testArena);
        // "SHA1 is not allowed for signature generation"
        if (!this.mdAlg.equals(EVP_MD.DIGEST_NAME_SHA1)) {
            // From version 3.4.0, the OpenSSL FIPS provider disables DSA signature generation when dsa-sign-disabled=1
            if (!this.alg.contains("withDSA") || fipsProviderVersion.compareTo(Version.of("3.4.0")) < 0) {
                this.signCtx.signInit(params, this.mdAlg, this.libCtx, null, privateKey);
            }
        }

        this.verifyCtx = openSsl.newEvpMdCtx(testArena);
        EVP_PKEY publicKey = KeyUtil.loadPublic(this.publicKeySpec, this.libCtx, this.testArena);
        this.verifyCtx.verifyInit(params, this.mdAlg, this.libCtx, null, publicKey);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    int getDigestLen() {
        return switch (this.mdAlg) {
            case EVP_MD.DIGEST_NAME_SHA1 -> 160;
            case EVP_MD.DIGEST_NAME_SHA2_224, EVP_MD.DIGEST_NAME_SHA3_224 -> 224;
            case EVP_MD.DIGEST_NAME_SHA2_256, EVP_MD.DIGEST_NAME_SHA3_256 -> 256;
            case EVP_MD.DIGEST_NAME_SHA2_384, EVP_MD.DIGEST_NAME_SHA3_384 -> 384;
            case EVP_MD.DIGEST_NAME_SHA2_512, EVP_MD.DIGEST_NAME_SHA3_512 -> 512;
            default -> throw new AssertionError("Unknown message digest algorithm");
        };
    }

    void checkSignatureGenerationAllowed() {
        Assume.assumeFalse("SHA1 is not allowed for signature generation",
                this.mdAlg.equals(EVP_MD.DIGEST_NAME_SHA1));
        Assume.assumeFalse("From version 3.4.0, the OpenSSL FIPS provider disables DSA signature generation",
                this.alg.endsWith("withDSA") && fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
        Assume.assumeFalse("From version 3.4.0, the OpenSSL FIPS provider checks that PSS salt length is " +
                "not larger than the message digest size", this.saltLen > getDigestLen() / 8);
    }

    void checkSignatureVerificationAllowed() {
        Assume.assumeFalse("From version 3.4.0, the OpenSSL FIPS provider checks that PSS salt length is " +
                        "not larger than the message digest size", this.saltLen > getDigestLen() / 8);
    }

    @Test
    public void signVerify() throws Exception {
        byte[] output = doSign();
        Assert.assertTrue(doVerify(output));
    }

    @Test
    public void verify() throws Exception {
        Assert.assertTrue(doVerify(this.signature));
    }

    @Test
    public void updateSignUpdateVerify() throws Exception {
        byte[] output = doUpdateSign();
        Assert.assertTrue(doUpdateVerify(output));
    }

    @Test
    public void updateVerify() throws Exception {
        Assert.assertTrue(doUpdateVerify(this.signature));
    }

    private byte[] doSign() throws Exception {
        checkSignatureGenerationAllowed();
        int outLen = signCtx.sign(this.data, 0, this.data.length, null, 0);
        byte[] output = new byte[outLen];
        outLen = signCtx.sign(this.data, 0, this.data.length, output, 0);
        if (outLen == output.length) {
            return output;
        } else {
            return Arrays.copyOfRange(output, 0, outLen);
        }
    }

    private boolean doVerify(byte[] input) throws Exception {
        checkSignatureVerificationAllowed();
        return verifyCtx.verify(this.data, 0, this.data.length, input, 0, input.length);
    }

    private byte[] doUpdateSign() throws Exception {
        checkSignatureGenerationAllowed();
        signCtx.signUpdate(this.data, 0, this.data.length);
        int outLen = signCtx.signFinal(null, 0);
        byte[] output = new byte[outLen];
        outLen = signCtx.signFinal(output, 0);

        if (outLen == output.length) {
            return output;
        } else {
            return Arrays.copyOfRange(output, 0, outLen);
        }
    }

    private boolean doUpdateVerify(byte[] input) throws Exception {
        checkSignatureVerificationAllowed();
        verifyCtx.verifyUpdate(this.data, 0, this.data.length);
        return verifyCtx.verifyFinal(input, 0, input.length);
    }

    @Test
    public void updateSignUpdateVerifyByteBuffer() throws Exception {
        updateSignUpdateVerifyByteBuffer(false);
    }

    @Test
    public void updateSignUpdateVerifyByteBufferDirect() throws Exception {
        updateSignUpdateVerifyByteBuffer(true);
    }

    public void updateSignUpdateVerifyByteBuffer(boolean direct) throws Exception {
        byte[] output = doUpdateSignByteBuffer(direct);
        Assert.assertTrue(doUpdateVerifyByteBuffer(output, direct));
    }

    @Test
    public void updateVerifyByteBuffer() throws Exception {
        updateVerifyByteBuffer(false);
    }

    @Test
    public void updateVerifyByteBufferDirect() throws Exception {
        updateVerifyByteBuffer(true);
    }

    public void updateVerifyByteBuffer(boolean direct) throws Exception {
        Assert.assertTrue(doUpdateVerifyByteBuffer(this.signature, direct));
    }

    private byte[] doUpdateSignByteBuffer(boolean direct) throws Exception {
        checkSignatureGenerationAllowed();

        ByteBuffer dataBB = direct ? ByteBuffer.wrap(this.data) : copyDirect(this.data);
        signCtx.signUpdate(dataBB);

        int outLen = signCtx.signFinal(null, 0);
        byte[] output = new byte[outLen];
        outLen = signCtx.signFinal(output, 0);

        if (outLen == output.length) {
            return output;
        } else {
            return Arrays.copyOfRange(output, 0, outLen);
        }
    }

    boolean doUpdateVerifyByteBuffer(byte[] input, boolean direct) throws Exception {
        checkSignatureVerificationAllowed();
        ByteBuffer dataBB = direct ? ByteBuffer.wrap(this.data) : copyDirect(this.data);
        verifyCtx.verifyUpdate(dataBB);
        return verifyCtx.verifyFinal(input, 0, input.length);
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }

    public static class PssParams implements Consumer<EVP_PKEY_CTX> {
        int saltLen;

        public PssParams(int saltLen) {
            this.saltLen = saltLen;
        }

        public void accept(EVP_PKEY_CTX evpPkeyCtx) {
            evpPkeyCtx.setParams(
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PAD_MODE, EVP_PKEY.PKEY_RSA_PAD_MODE_PSS),
                    OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_RSA_PSS_SALTLEN, saltLen));
        }
    }
}
