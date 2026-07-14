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
import java.nio.charset.StandardCharsets;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assume;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class EvpPkeyTest extends EvpTest {
    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    static final String KEY_NAME = "RSA";
    static final String KEY_DESCRIPTION = "OpenSSL RSA implementation";

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters
    static final Set<String> RSA_KEY_FROM_DATA_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "e", "d", "n", "rsa-exponent1", "rsa-exponent2", "rsa-factor1",  "rsa-factor2", "rsa-coefficient1"));
    static final Set<String> RSA_KEY_GETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList(
            "bits", "security-bits", "max-size", "default-digest",
            "e", "d", "n", "rsa-exponent1", "rsa-exponent2", "rsa-factor1",  "rsa-factor2", "rsa-coefficient1"));
    static final Set<String> RSA_KEY_SETTABLE_PARAM_KEYS = EMPTY_SET;

    static final Set<String> RSA_KEY_TYPE_NAMES = new HashSet<>(Arrays.asList(
            "RSA", "rsaEncryption", "2.5.8.1.1", "1.2.840.113549.1.1.1"));

    static final int BITS = 2048;

    private Version fipsProviderVersion;

    private String alg;
    private RSAPrivateCrtKeySpec keySpec;
    private EVP_PKEY key;
    private EVP_PKEY_CTX ctx;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        this.alg = KEY_NAME;
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg(this.alg).secParam(Integer.toString(BITS)));
        this.keySpec = (RSAPrivateCrtKeySpec) KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.key = KeyUtil.loadPrivate(this.keySpec, this.libCtx, this.testArena);
        this.ctx = libCtx.newPkeyCtx(this.key, null, this.testArena);
    }

    @Test
    public void newPkey() {
        assertNotNull(openSsl.newEvpPkey(this.testArena));
    }

    @Test
    public void isA() {
        assertTrue(key.isA(alg));
        assertTrue(ctx.isA(alg));
    }

    @Test
    public void typeName() {
        assertEquals(alg, key.typeName());
    }

    @Test
    public void forEachTypeName() throws Exception {
        key.forEachTypeName(typeName -> assertTrue(RSA_KEY_TYPE_NAMES.contains(typeName)));
    }

    @Test
    public void description() {
        String test = key.description();
        assertEquals(KEY_DESCRIPTION, key.description());
    }

    @Test
    public void providerName() {
        assertEquals("fips", key.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = key.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(RSA_KEY_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void settableParams() throws Exception {
        OsslParamBuffer params = key.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(RSA_KEY_SETTABLE_PARAM_KEYS));
    }

    @Test
    public void getParams() throws Exception {
        OsslParamBuffer bitsParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("bits", OSSL_PARAM.Type.INTEGER));

        key.getParams(bitsParam);
        assertTrue(bitsParam.locate("bits").isPresent());
        int bits = bitsParam.locate("bits").get().intValue();
        assertEquals(BITS, bits);
    }

    @Test
    public void getEmptyParams() throws Exception {
        // This test increases code coverage
        key.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void setParams() throws Exception {
        // This test increases code coverage
        key.setParams(this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", 3)));
    }

    @Test
    public void setEmptyParams() throws Exception {
        // This test increases code coverage
        key.setParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void dup() throws Exception {
        EVP_PKEY dupKey = key.dup(this.testArena);

        OsslParamBuffer keyParams = key.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        OsslParamBuffer dupKeyParams = dupKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(keyParams, dupKeyParams);

        EVP_PKEY_CTX dupCtx = ctx.dup(this.testArena);
        dupCtx.isA(this.alg);
    }

    @Test
    public void dupOfAuto() throws Exception {
        EVP_PKEY dupKey = key.dup();

        OsslParamBuffer keyParams = key.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        OsslParamBuffer dupKeyParams = dupKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(keyParams, dupKeyParams);

        EVP_PKEY_CTX dupCtx = ctx.dup();
        dupCtx.isA(this.alg);
    }

    @Test(expected = IllegalStateException.class)
    public void active() {
        EVP_PKEY dupKey = key.dup();
        dupKey.free();
        dupKey.isA(alg);
    }

    @Test
    public void upRef() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            key.upRef(confinedArena);
        }
        // Confirm rand is still live
        assertEquals(alg, key.typeName());
    }

    @Test
    public void todata() throws Exception {
        OsslParamBuffer params = key.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertTrue(params.locate("d").isPresent());
        BigInteger privateExponent = params.locate("d").get().bigIntegerValue();
        assertEquals(keySpec.getPrivateExponent(), privateExponent);
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = ctx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertEquals(EMPTY_SET, paramKeys);
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = ctx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertEquals(EMPTY_SET, paramKeys);
    }

    @Test
    public void fromdataSettableParams() throws Exception {
        OsslParamBuffer params = ctx.fromdataSettableParams(EVP_PKEY.Selection.PKEY_KEYPAIR);
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(RSA_KEY_FROM_DATA_SETTABLE_PARAM_KEYS));
    }

    @Test
    public void ctxSetGetParams() throws Exception {
        String key = "digest";

        // A PKEY ctx must be initialised before parameters can be set/get
        ctx.encryptInit();

        // Set a parameter to get (later).
        ctx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.of(key, EVP_MD.DIGEST_NAME_SHA2_256)));

        // Get the parameter (set above).
        OsslParamBuffer digestParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of(key, OSSL_PARAM.Type.UTF8_STRING, EVP_MD.DIGEST_NAME_SHA2_256.getBytes(StandardCharsets.UTF_8).length + 1));
        ctx.getParams(digestParam);

        // Verify that it is the expected value
        assertTrue(digestParam.locate(key).isPresent());
        String digest = digestParam.locate(key).get().stringValue();
        assertEquals(EVP_MD.DIGEST_NAME_SHA2_256, digestParam.locate(key).get().stringValue());
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        ctx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        ctx.setParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void generateParams() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        Assume.assumeFalse("From version 3.4.0, the OpenSSL FIPS provider disables DSA key/parameter generation when dsa-sign-disabled=1",
                fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
        EVP_PKEY_CTX dsaCtx = libCtx.newPkeyCtx("DSA", null, this.testArena);
        dsaCtx.paramgenInit();
        dsaCtx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_FFC_PBITS, BITS)));
        EVP_PKEY dsaParams = dsaCtx.generate(this.testArena);

        OsslParamBuffer bitsParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("bits", OSSL_PARAM.Type.INTEGER));
        dsaParams.getParams(bitsParam);
        assertTrue(bitsParam.locate("bits").isPresent());
        assertEquals(BITS, bitsParam.locate("bits").get().intValue());
    }

    @Test
    public void generateKey() throws Exception {
        EVP_PKEY_CTX rsaCtx = libCtx.newPkeyCtx("RSA", null, this.testArena);
        rsaCtx.keygenInit();
        rsaCtx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_BITS, BITS)));
        EVP_PKEY rsaKey = rsaCtx.generate(this.testArena);

        OsslParamBuffer bitsParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("bits", OSSL_PARAM.Type.INTEGER));
        rsaKey.getParams(bitsParam);
        assertTrue(bitsParam.locate("bits").isPresent());
        assertEquals(BITS, bitsParam.locate("bits").get().intValue());
    }

    @Test
    public void generateKeyOfAuto() throws Exception {
        EVP_PKEY_CTX rsaCtx = libCtx.newPkeyCtx("RSA", null, this.testArena);
        rsaCtx.keygenInit();
        rsaCtx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_BITS, BITS)));
        EVP_PKEY rsaKey = rsaCtx.generate();

        OsslParamBuffer bitsParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("bits", OSSL_PARAM.Type.INTEGER));
        rsaKey.getParams(bitsParam);
        assertTrue(bitsParam.locate("bits").isPresent());
        assertEquals(BITS, bitsParam.locate("bits").get().intValue());
    }

    @Test
    public void fromData() throws Exception {
        EVP_PKEY_CTX pkeyCtx = libCtx.newPkeyCtx("RSA", null, this.testArena);
        pkeyCtx.fromdataInit();

        OsslParamBuffer in = this.openSsl.dataParamBuffer(this.testArena, KeyUtil.newParams(this.keySpec).toArray(OSSL_PARAM.EMPTY_ARRAY));
        EVP_PKEY pKey = pkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena, in);
        assertNotNull(pKey);

        OsslParamBuffer out = pKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(in, out);

        // Repeat test using 'OSSL_PARAM... params' instead of 'OsslParamBuffer params'
        pKey = pkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena, in.asArray());
        assertNotNull(pKey);

        out = pKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(in, out);
    }

    @Test
    public void fromDataOfAuto() throws Exception {
        EVP_PKEY_CTX pkeyCtx = libCtx.newPkeyCtx("RSA", null, this.testArena);
        pkeyCtx.fromdataInit();
        OsslParamBuffer in = this.openSsl.dataParamBuffer(this.testArena, KeyUtil.newParams(this.keySpec).toArray(OSSL_PARAM.EMPTY_ARRAY));
        EVP_PKEY pKey = pkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, in);
        assertNotNull(pKey);

        OsslParamBuffer out = pKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(in, out);

        // Repeat test using 'OSSL_PARAM... params' instead of 'OsslParamBuffer params'
        pKey = pkeyCtx.fromdata(EVP_PKEY.Selection.PKEY_KEYPAIR, in.asArray());
        assertNotNull(pKey);

        out = pKey.todata(EVP_PKEY.Selection.PKEY_KEYPAIR, this.testArena);
        assertParamsEquals(in, out);
    }

    // Negative tests

    @Test(expected = RuntimeException.class)
    public void forEachTypeNameThrowsRuntimeExceptionNeg() {
        key.forEachTypeName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = AssertionError.class)
    public void forEachTypeNameThrowsExceptionNeg() {
        key.forEachTypeName(name -> EvpPkeyTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachTypeNameThrowsErrorNeg() {
        key.forEachTypeName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    private void assertParamsEquals(OsslParamBuffer params1, OsslParamBuffer params2) {
        for (OSSL_PARAM param: params1.asArray()) {
            assertTrue(params1.locate(param.key).isPresent());
            assertTrue(params2.locate(param.key).isPresent());
            assertEquals(params1.locate(param.key).get().intValue(), params1.locate(param.key).get().intValue());
        }
    }
}
