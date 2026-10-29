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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_LIB_CRYPTO;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_LIB_EVP;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_LIB_OFFSET;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_LIB_RAND;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_LIB_SYS;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_RFLAG_COMMON;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_RFLAG_FATAL;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.ERR_R_MALLOC_FAILURE;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.EVP_R_MESSAGE_DIGEST_IS_NULL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class OpenSslTest {

    OpenSsl openSsl;
    OsslArena testArena;

    @Before
    public void setUp() throws Exception {
        openSsl = OpenSsl.getInstance();
        testArena = OsslArena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        testArena.close();
    }

    @Test
    public void initCrypto() {
        // "Numerous internal OpenSSL functions call OPENSSL_init_crypto(). Therefore, in order to
        // perform nondefault initialisation, OPENSSL_init_crypto() MUST be called by application code
        // prior to any other OpenSSL function calls."
        // This unit test does not guarantee that this call to OPENSSL_init_crypto happens prior to any other OpenSSL
        // function calls.  It simply tests that the API can be called from Java.
        openSsl.initCrypto(OpenSsl.InitOption.NO_LOAD_CRYPTO_STRINGS);
    }

    @Test
    public void getDefaultOsslLibCtx() {
        assertNotNull(openSsl.getDefaultOsslLibCtx());
    }

    @Test
    public void version() {
        String expected = openSsl.versionMajor() + "." + openSsl.versionMinor() + "." + openSsl.versionPatch();
        assertEquals(expected, openSsl.versionString(OpenSsl.VersionStringSelector.VERSION_STRING));
    }

    @Test
    public void infoString() {
        assertEquals(File.separator, openSsl.infoString(OpenSsl.InfoStringSelector.DIR_FILENAME_SEPARATOR));
    }

    @Test
    public void versionBuildMetadataString() {
        // OPENSSL_version_build_metadata() will return an empty string unless OpenSSL
        // was built with custom version build metadata. Because the value depends on the
        // build configuration, only verify it when an expected value is provided.
        String actual = openSsl.versionBuildMetadataString();
        String expected = System.getProperty("jipher.test.openssl.versionBuildMetadataString");
        if (expected != null) {
            assertEquals(expected, actual);
        }
    }

    @Test
    public void errors() {
        openSsl.clearErrorQueue();
        assertEquals(0, openSsl.peekLastError());
        assertEquals(0, openSsl.peekError());
        assertEquals(0, openSsl.getError());

        // Purposefully cause an error to be added to the thread's OpenSSL error queue (without calling an API that
        // returns error return code) by calling EVP_MAC_CTX_get_params on an _uninitialized_ EVP_MAC_CTX.
        // (Note: OpenSSL API calls that return an error return code trigger an OpenSSLException to be created.
        //        Construction of the OpenSSLException clears the thread's OpenSSL error queue. Hence, we employ
        //        and OpenSSL API call here that adds errors to the thread's OpenSSL error queue but does not
        //        return an error return code.)
        // This takes advantage of an implementation detail present in 3.0 to 3.5 which may (though is unlikely to)
        // change in later versions.
        EVP_MAC mac = LibCtx.getInstance().fetchMac("HMAC", null, testArena);
        EVP_MAC_CTX ctx = openSsl.newEvpMacCtx(mac, testArena);
        ctx.getParams(openSsl.templateParamBuffer(testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER)));

        int expectedErrorCode = ERR_LIB_EVP << 23 | EVP_R_MESSAGE_DIGEST_IS_NULL;
        assertEquals(expectedErrorCode, openSsl.peekLastError());
        assertEquals(expectedErrorCode, openSsl.peekError());
        assertEquals(expectedErrorCode, openSsl.getError());
        assertEquals(0, openSsl.peekLastError());

        // Trigger the error again.
        ctx.getParams(openSsl.templateParamBuffer(testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER)));
        List<String> errorMessages = new ArrayList<>(1);
        ctx.getParams(openSsl.templateParamBuffer(testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER)));
        openSsl.forEachError(errorMessages::add);
        assertEquals(0, openSsl.peekLastError());

        assertEquals(2, errorMessages.size());
        for (String errorMessage : errorMessages) {
            assertTrue(errorMessage.contains("message digest is null"));
        }

        // Trigger the error again.
        ctx.getParams(openSsl.templateParamBuffer(testArena, OSSL_PARAM.of("size", OSSL_PARAM.Type.INTEGER)));
        openSsl.clearErrorQueue();
        assertEquals(0, openSsl.peekLastError());
    }

    @Test
    public void openSslExceptionUtilMethods() {
        OpenSslException systemError = new OpenSslException("System error", null, 0x80000123);
        assertEquals("System error", systemError.getMessage());
        assertNull(systemError.getCause());
        assertTrue(systemError.isSystemError());
        assertEquals(ERR_LIB_SYS, systemError.getLib());
        assertEquals(0, systemError.getRFlags());
        assertEquals(0x123, systemError.getReason());
        assertFalse(systemError.isFatalError());
        assertFalse(systemError.isCommonError());

        OpenSslException mallocFailure = new OpenSslException("malloc failure", null, (ERR_LIB_CRYPTO << ERR_LIB_OFFSET) | ERR_R_MALLOC_FAILURE);
        assertEquals("malloc failure", mallocFailure.getMessage());
        assertNull(mallocFailure.getCause());
        assertFalse(mallocFailure.isSystemError());
        assertEquals(ERR_LIB_CRYPTO, mallocFailure.getLib());
        assertEquals(ERR_RFLAG_FATAL | ERR_RFLAG_COMMON, mallocFailure.getRFlags());
        assertEquals(ERR_R_MALLOC_FAILURE, mallocFailure.getReason());
        assertTrue(mallocFailure.isFatalError());
        assertTrue(mallocFailure.isCommonError());

        OpenSslException randFailure = new OpenSslException("rand failure", null, (ERR_LIB_RAND << ERR_LIB_OFFSET) | 0x01);
        assertEquals(ERR_LIB_RAND, randFailure.getLib());
    }

    @Test(expected = OutOfMemoryError.class)
    public void testMallocFailure() {
        openSsl.templateParamBuffer(testArena, OSSL_PARAM.of("big", OSSL_PARAM.Type.OCTET_STRING, 0x4000000000000000L));
    }
}
