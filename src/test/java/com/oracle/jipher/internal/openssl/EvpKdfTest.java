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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assert;
import org.junit.Test;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jiphertest.testdata.PbkdfTestVector;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

public class EvpKdfTest extends EvpTest {

    static final int MIN_SECURITY_STRENGTH = 112; //bits
    static final int MIN_SALT_LENGTH = 128; //bits
    static final int MIN_ITERATION_COUNT = 1000;

    static final Set<String> EMPTY_SET = Collections.<String>emptySet();

    static final long MAX_UNSIGNED_LONG = -1;
    static final long MAX_SIZE = MAX_UNSIGNED_LONG;

    static final String JCA_ALG = "PBKDF2WithHmacSHA256";
    static final String KDF_ALG = EVP_KDF.KDF_NAME_PBKDF2;
    static final String MD_ALG = EVP_MD.DIGEST_NAME_SHA2_256;

    static final Set<String> PBKDF2_KDF_NAMES = new HashSet<>(Arrays.asList("PBKDF2", "1.2.840.113549.1.5.12"));
    static final String PBKDF2_KDF_DESCRIPTION = null;

    // The following are the PARAM_KEYS in OpenSSL version 3.0.0. Later versions may support additional parameters.
    static final Set<String> PBKDF2_KDF_GETTABLE_PARAMS = EMPTY_SET;
    static final Set<String> PBKDF2_KDF_CTX_GETTABLE_PARAM_KEYS = new HashSet<>(List.of("size"));
    static final Set<String> PBKDF2_KDF_CTX_SETTABLE_PARAM_KEYS = new HashSet<>(Arrays.asList("salt",
            "pass", "pkcs5", "digest", "iter", "properties"));

    static final int MIN_KEY_LEN_BITS = 112;

    private Version fipsProviderVersion;

    EVP_KDF kdf;
    EVP_KDF_CTX kdfCtx;
    OsslParamBuffer kdfParams;
    private byte[] derivedKey;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        PbkdfTestVector tv = TestData.getFirst(PbkdfTestVector.class, alg(JCA_ALG));
        this.kdf = this.libCtx.fetchKdf(KDF_ALG, null, testArena);
        this.kdfCtx = this.openSsl.newEvpKdfCtx(kdf);
        this.derivedKey = tv.getDk();

        // Setup KDF parameters
        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, tv.getSalt());
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, tv.getIterationCount());
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, MD_ALG);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, Util.utf8Encode(tv.getPasswordChars()));
        this.kdfParams = this.openSsl.dataParamBuffer(this.testArena, passParam, saltParam, iterParam, dgstParam);
    }

    @Test
    public void isA() {
        assertTrue(kdf.isA(KDF_ALG));
    }

    @Test
    public void name() {
        assertEquals(KDF_ALG, kdf.name());
    }

    @Test
    public void forEachName() throws Exception {
        kdf.forEachName(name -> assertTrue(PBKDF2_KDF_NAMES.contains(name)));
    }

    @Test
    public void description() {
        assertEquals(PBKDF2_KDF_DESCRIPTION, kdf.description());
    }

    @Test
    public void providerName() {
        assertEquals("fips", kdf.providerName());
    }

    @Test
    public void gettableParams() throws Exception {
        OsslParamBuffer params = kdf.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertEquals(PBKDF2_KDF_GETTABLE_PARAMS, paramKeys);
    }

    @Test
    public void getParams() throws Exception {
        // This test increases code coverage
        kdf.getParams(this.openSsl.templateParamBuffer(this.testArena, OSSL_PARAM.of("nonsense", OSSL_PARAM.Type.INTEGER)));
    }

    @Test
    public void getEmptyParams() throws Exception {
        // This test increases code coverage
        kdf.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void gettableCtxParams() throws Exception {
        OsslParamBuffer params = kdf.gettableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(PBKDF2_KDF_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void settableCtxParams() throws Exception {
        OsslParamBuffer params = kdf.settableCtxParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(PBKDF2_KDF_CTX_SETTABLE_PARAM_KEYS));
    }

    @Test
    public void upRef() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            kdf.upRef(confinedArena);
        }
        // Confirm md is still live
        assertEquals(KDF_ALG, kdf.name());
    }

    @Test
    public void ctxGettableParams() throws Exception {
        OsslParamBuffer params = kdfCtx.gettableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(PBKDF2_KDF_CTX_GETTABLE_PARAM_KEYS));
    }

    @Test
    public void ctxSettableParams() throws Exception {
        OsslParamBuffer params = kdfCtx.settableParams();
        Stream<String> stringStream = Arrays.stream(params.asArray()).map(param -> param.key);
        Set<String> paramKeys = stringStream.collect(Collectors.toSet());
        assertTrue(paramKeys.containsAll(PBKDF2_KDF_CTX_SETTABLE_PARAM_KEYS));
    }

    @Test
    public void kdfSize() throws Exception {
        assertEquals(MAX_SIZE, kdfCtx.kdfSize());
    }

    @Test
    public void derive() throws Exception {
        byte[] output = new byte[this.derivedKey.length];
        kdfCtx.derive(output, this.kdfParams);
        assertArrayEquals(this.derivedKey, output);

        // Repeat test using 'OSSL_PARAM... params' instead of 'OsslParamBuffer params'
        kdfCtx.derive(output, this.kdfParams.asArray());
        assertArrayEquals(this.derivedKey, output);
    }

    @Test
    public void deriveByteBuffer() throws Exception {
        deriveByteBuffer(false);
    }

    @Test
    public void deriveByteBufferDirect() throws Exception {
        deriveByteBuffer(true);
    }

    public void deriveByteBuffer(boolean direct) throws Exception {
        int outLen = this.derivedKey.length;
        ByteBuffer output = direct ? ByteBuffer.allocateDirect(outLen) : ByteBuffer.allocate(outLen);

        kdfCtx.derive(output, this.kdfParams);
        assertFalse(output.hasRemaining());

        byte[] derivedKeyBytes = new byte[output.position()];
        output.flip().get(derivedKeyBytes);
        assertArrayEquals(this.derivedKey, derivedKeyBytes);

        // Repeat test using 'OSSL_PARAM... params' instead of 'OsslParamBuffer params'
        output.rewind();
        kdfCtx.derive(output, this.kdfParams.asArray());
        assertFalse(output.hasRemaining());

        output.flip().get(derivedKeyBytes);
        assertArrayEquals(this.derivedKey, derivedKeyBytes);
    }

    @Test
    public void dup() throws InterruptedException {
        // None of the KDFs in OpenSSL support the dupctx method.
        // Consequently, this test simply increases code coverage at the java layer.
        try {
            kdfCtx.dup(testArena);
        } catch (Exception e) {
            assertEquals("EVP_KDF_CTX_dup failed", e.getMessage());
        }
    }

    @Test
    public void dupOfAuto() throws InterruptedException {
        // None of the KDFs in OpenSSL support the dupctx method.
        // Consequently, this test simply increases code coverage at the java layer.
        try {
            kdfCtx.dup();
        } catch (Exception e) {
            assertEquals("EVP_KDF_CTX_dup failed", e.getMessage());
        }
    }

    @Test
    public void reset() {
        byte[] output = new byte[this.derivedKey.length];
        kdfCtx.derive(output, this.kdfParams);
        assertArrayEquals(this.derivedKey, output);

        kdfCtx.reset();
        kdfCtx.derive(output, this.kdfParams);
        assertArrayEquals(this.derivedKey, output);
    }

    @Test
    public void ctxGetParams() throws Exception {
        OsslParamBuffer sizeParam = this.openSsl.templateParamBuffer(this.testArena,
                OSSL_PARAM.of("size", OSSL_PARAM.Type.UNSIGNED_INTEGER, Long.BYTES));
        kdfCtx.getParams(sizeParam);
        assertTrue(sizeParam.locate("size").isPresent());
        assertEquals(MAX_SIZE, sizeParam.locate("size").get().intValue());
    }

    @Test
    public void ctxSetParams() throws Exception {
        OsslParamBuffer digestParam = this.openSsl.dataParamBuffer(this.testArena, OSSL_PARAM.of("digest", MD_ALG));
        kdfCtx.setParams(digestParam);
    }

    @Test
    public void ctxGetEmptyParams() throws Exception {
        // This test increases code coverage
        kdfCtx.getParams(this.openSsl.emptyParamBuffer());
    }

    @Test
    public void ctxSetEmptyParams() throws Exception {
        // This test increases code coverage
        kdfCtx.setParams(this.openSsl.emptyParamBuffer());
    }

    @Test (expected = OpenSslException.class)
    public void invalidIterationCount() {
        byte[] salt = new byte[MIN_SALT_LENGTH / 8];
        byte[] password = new byte[8];
        byte[] output = new byte[16];

        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, MIN_ITERATION_COUNT - 1);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, MD_ALG);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, password);

        try {
            kdfCtx.derive(output, saltParam, iterParam, dgstParam, passParam);
        } catch (OpenSslException e) {
            Assert.assertTrue(e.getMessage().contains("invalid iteration count"));
            throw e;
        }
    }

    @Test (expected = OpenSslException.class)
    public void invalidSaltLength() {
        byte[] salt = new byte[MIN_SALT_LENGTH / 8 - 1];
        byte[] password = new byte[8];
        byte[] output = new byte[16];

        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, MIN_ITERATION_COUNT);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, MD_ALG);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, password);

        try {
            kdfCtx.derive(output, saltParam, iterParam, dgstParam, passParam);
        } catch (OpenSslException e) {
            Assert.assertTrue(e.getMessage().contains("invalid salt length"));
            throw e;
        }
    }

    @Test
    public void invalidPasswordLength() {
        byte[] salt = new byte[MIN_SALT_LENGTH / 8];
        byte[] password = new byte[8 - 1];
        byte[] output = new byte[16];

        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, MIN_ITERATION_COUNT);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, MD_ALG);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, password);
        String fipsProviderName = FipsProviderInfoUtil.getName();
        String fipsProviderVersion = FipsProviderInfoUtil.getVersionString();
        try {
            kdfCtx.derive(output, saltParam, iterParam, dgstParam, passParam);
            Assert.assertFalse(fipsProviderName.contains("Linux 9"));
        } catch (OpenSslException e) {
            Assert.assertTrue(fipsProviderVersion.startsWith("3.0.7") || fipsProviderVersion.equals("1.2.0"));
            Assert.assertTrue(e.getMessage().contains("invalid key length")); // (RHE/O)L error message uses 'key' not 'password'
        }
    }

    @Test (expected = OpenSslException.class)
    public void keySizeTooSmall() {
        byte[] salt = new byte[MIN_SALT_LENGTH / 8];
        byte[] password = new byte[8];
        byte[] output = new byte[MIN_SECURITY_STRENGTH / 8 - 1];

        OSSL_PARAM saltParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SALT, salt);
        OSSL_PARAM iterParam = OSSL_PARAM.ofUnsigned(EVP_KDF.KDF_PARAM_ITER, MIN_ITERATION_COUNT);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, MD_ALG);
        OSSL_PARAM passParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_PASSWORD, password);

        try {
            kdfCtx.derive(output, saltParam, iterParam, dgstParam, passParam);
        } catch (OpenSslException e) {
            Assert.assertTrue(e.getMessage().contains("key size too small"));
            throw e;
        }
    }


    @Test
    public void tls1Prf() {
        EVP_KDF tls1Prf  = this.libCtx.fetchKdf(EVP_KDF.KDF_NAME_TLS1_PRF, null, testArena);
        EVP_KDF_CTX tls1PrfCtx = this.openSsl.newEvpKdfCtx(tls1Prf);

        byte[] secret = new byte[MIN_SECURITY_STRENGTH / 8];
        byte[] seed = new byte[16];
        byte[] out = new byte[16];
        byte[] expected = new byte[]{49, 110, 91, -110, -89, 16, 103, -21, -28, 96, 119, -128, -98, 116, 70, 7};

        OSSL_PARAM scrtParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SECRET, secret);
        OSSL_PARAM seedParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SEED, seed);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA2_256);

        tls1PrfCtx.derive(out, scrtParam, seedParam, dgstParam);

        assertArrayEquals(expected, out);
    }

    @Test // Throws OpenSslException: EVP_KDF_derive failed, with digest not allowed if tls1-prf-digest-check=1
    public void tls1PrfDisallowedDigestAlgorithm() {
        EVP_KDF tls1Prf  = this.libCtx.fetchKdf(EVP_KDF.KDF_NAME_TLS1_PRF, null, testArena);
        EVP_KDF_CTX tls1PrfCtx = this.openSsl.newEvpKdfCtx(tls1Prf);

        byte[] secret = new byte[MIN_SECURITY_STRENGTH / 8];
        byte[] seed = new byte[16];
        byte[] out = new byte[16];

        OSSL_PARAM scrtParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SECRET, secret);
        OSSL_PARAM seedParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SEED, seed);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA1);

        try {
            tls1PrfCtx.derive(out, scrtParam, seedParam, dgstParam);
            assumeTrue("From version 3.4.0, the OpenSSL FIPS provider disallows digests other than " +
                            "SHA-256, SHA-384 or SHA-512 when deriving a key by TLS1 KDF when tls1-prf-digest-check=1",
                    fipsProviderVersion.compareTo(Version.of("3.4.0")) < 0);
        } catch (OpenSslException e) {
            // tls1-prf-digest-check was added in 3.4.0
            assumeTrue("From version 3.4.0, the OpenSSL FIPS provider disallows digests other than " +
                            " SHA-256, SHA-384 or SHA-512 when deriving a key by TLS1 KDF when tls1-prf-digest-check=1",
                    fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
            assumeTrue(e.getMessage().contains("digest not allowed"));
        }
    }

    @Test // Throws OpenSslException: EVP_KDF_derive failed, with invalid key length if tls1-prf-key-check=1
    public void tls1PrfShortKey() {
        EVP_KDF tls1Prf  = this.libCtx.fetchKdf(EVP_KDF.KDF_NAME_TLS1_PRF, null, testArena);
        EVP_KDF_CTX tls1PrfCtx = this.openSsl.newEvpKdfCtx(tls1Prf);

        byte[] secret = new byte[MIN_SECURITY_STRENGTH / 8 - 1];
        byte[] seed = new byte[16];
        byte[] out = new byte[16];

        OSSL_PARAM scrtParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SECRET, secret);
        OSSL_PARAM seedParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_SEED, seed);
        OSSL_PARAM dgstParam = OSSL_PARAM.of(EVP_KDF.KDF_PARAM_DIGEST, EVP_MD.DIGEST_NAME_SHA2_256);

        try {
            tls1PrfCtx.derive(out, scrtParam, seedParam, dgstParam);
            assumeTrue("From version 3.4.0, the OpenSSL FIPS provider disallows digests other than " +
                            "SHA-256, SHA-384 or SHA-512 when deriving a key by TLS1 KDF when tls1-prf-digest-check=1",
                    fipsProviderVersion.compareTo(Version.of("3.4.0")) < 0);
        } catch (OpenSslException e) {
            // tls1-prf-digest-check was added in 3.4.0
            assumeTrue("From version 3.4.0, the OpenSSL FIPS provider disallows digests other than " +
                            "SHA-256, SHA-384 or SHA-512 when deriving a key by TLS1 KDF when tls1-prf-digest-check=1",
                    fipsProviderVersion.compareTo(Version.of("3.4.0")) >= 0);
            assumeTrue(e.getMessage().contains("invalid key length"));
        }
    }

    // Negative tests

    @Test(expected = RuntimeException.class)
    public void forEachNameThrowsRuntimeExceptionNeg() {
        kdf.forEachName(name -> {
            throw new RuntimeException("forEachConsumerFailed");
        });
    }

    @Test(expected = AssertionError.class)
    public void forEachNameThrowsExceptionNeg() {
        kdf.forEachName(name -> EvpKdfTest.throwAsUnchecked(new Exception("forEachConsumerFailed")));
    }

    @Test(expected = Error.class)
    public void forEachNameThrowsErrorNeg() {
        kdf.forEachName(name -> {
            throw new Error("forEachConsumerFailed");
        });
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Test (expected = IllegalArgumentException.class)
    public void ctxGetReadOnlyParams() throws Exception {
        OsslParamBuffer readOnlyParams = kdfCtx.gettableParams();
        try {
            kdfCtx.getParams(readOnlyParams);
        } catch (IllegalArgumentException e) {
            assertEquals("Read-only OsslParamBuffer supplied", e.getMessage());
            throw e;
        }
    }

    @Test
    public void derivedMissingParametersNeg() throws Exception {
        ByteBuffer output = ByteBuffer.allocate(this.derivedKey.length);
        OsslParamBuffer noParams = this.openSsl.dataParamBuffer(this.testArena);
        try {
            kdfCtx.derive(output, noParams);
            fail("Expected OpenSslException: missing");
        } catch (OpenSslException e) {
            assertTrue(e.getMessage().contains("missing"));
        }
    }

    @Test
    public void derivedKeyLenTooSmallNeg() throws Exception {
        byte[] output = new byte[MIN_KEY_LEN_BITS / 8 - 1];

        try {
            kdfCtx.derive(output, this.kdfParams);
            fail("Expected OpenSslException: key size too small");
        } catch (OpenSslException e) {
            // The SPI layer will validate parameters passed to the `kdfCtx` before calling
            // `kdfCtx.derive` and thus this OpenSslException will not be thrown in practice.
            assertTrue(e.getMessage().contains("key size too small"));
        }
    }

    @Test
    public void derivedKeyLenTooSmallByteBufferlNeg() throws Exception {
        ByteBuffer output = ByteBuffer.allocate(MIN_KEY_LEN_BITS / 8 - 1);
        try {
            kdfCtx.derive(output, this.kdfParams);
            fail("Expected OpenSslException: key size too small");
        } catch (OpenSslException e) {
            // The SPI layer will validate parameters passed to the `kdfCtx` before calling
            // `kdfCtx.derive` and thus this OpenSslException will not be thrown in practice.
            assertTrue(e.getMessage().contains("key size too small"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void readOnlyOutputByteBufferNeg() {
        ByteBuffer output = ByteBuffer.allocate(this.derivedKey.length).asReadOnlyBuffer();
        kdfCtx.derive(output, this.kdfParams);
    }

    @Test(expected = IllegalArgumentException.class)
    public void readOnlyOutputByteBufferDirectNeg() {
        ByteBuffer output = ByteBuffer.allocateDirect(this.derivedKey.length).asReadOnlyBuffer();
        kdfCtx.derive(output, this.kdfParams);
    }
}
