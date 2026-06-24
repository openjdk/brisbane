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

import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collection;
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
import static org.junit.Assert.assertArrayEquals;

/**
 * Tests
 *    EVP_PKEY_sign_init_ex,   EVP_PKEY_sign,
 *    EVP_PKEY_verify_init_ex, EVP_PKEY_verify
 *  using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpPkeySignatureVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        Predicate<Object[]> nonDigestSignature = EvpPkeySignatureVectorTest::isAcceptableSignature;

        return TestData.forParameterized(SignatureTestVector.class)
                .stream().filter(nonDigestSignature).collect(Collectors.toList());
    }

    private Version fipsProviderVersion;

    private final String alg;
    private final KeySpec privateKeySpec;
    private final KeySpec publicKeySpec;
    private final byte[] data;
    private final byte[] signature;

    EVP_PKEY_CTX signCtx;
    EVP_PKEY_CTX verifyCtx;

    static boolean isAcceptableSignature(Object[] param) {
        String alg = ((SignatureTestVector) param[1]).getAlg().toUpperCase();
        return alg.startsWith("NONE") || alg.equals("ML-DSA");
    }

    static boolean isDeterministic(String alg) {
        return !alg.contains("DSA") && !alg.contains("ECDSA");
    }

    public EvpPkeySignatureVectorTest(String description, SignatureTestVector tv) throws Exception {
        this.alg = tv.getAlg();

        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        this.privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.data = tv.getData();
        this.signature = tv.getSignature();

        if (this.alg.contains("withDSA")) {
            Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported());
        } else if (this.alg.equals("ML-DSA")) {
            Assume.assumeTrue(FipsProviderInfoUtil.isMLDSASupported());
        }
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        EVP_PKEY privateKey = KeyUtil.loadPrivate(this.privateKeySpec, this.libCtx, this.testArena);
        // OpenSSL 3.4.0 added support for dsa-sign-disabled
        if (!this.alg.contains("withDSA") || fipsProviderVersion.compareTo(Version.of("3.4.0")) < 0) {
            this.signCtx = libCtx.newPkeyCtx(privateKey, null, this.testArena);
            this.signCtx.signInit();
        }

        EVP_PKEY publicKey = KeyUtil.loadPublic(this.publicKeySpec, this.libCtx, this.testArena);
        this.verifyCtx = libCtx.newPkeyCtx(publicKey, null, this.testArena);
        this.verifyCtx.verifyInit();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    void checkSignatureGenerationAllowed() {
        Assume.assumeFalse("From version 3.4.0, the OpenSSL FIPS provider disables DSA signature generation " +
                        " when dsa-sign-disabled=1",
                this.alg.endsWith("withDSA") && fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
    }

    @Test
    public void signVerify() throws Exception {
        byte[] output = doSign();
        if (isDeterministic(this.alg)) {
            assertArrayEquals(this.signature, output);
        }
        Assert.assertTrue(doVerify(output));
    }

    @Test
    public void verify() throws Exception {
        Assert.assertTrue(doVerify(this.signature));
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
        return verifyCtx.verify(this.data, 0, this.data.length, input, 0, input.length);
    }
}
