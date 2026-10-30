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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LifeCycleHookTest {

    static final List<CallbackRecord> CALLBACK_RECORD_LIST = Collections.synchronizedList(new ArrayList<>());

    OpenSsl openSsl;
    OSSL_LIB_CTX libCtx;
    OsslArena testArena;

    @Before
    public void setUp() throws Exception {
        openSsl = OpenSsl.getInstance();
        libCtx = LibCtx.getInstance();
        testArena = OsslArena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        testArena.close();
    }

    @Test
    public void allocDeallocCipher() {
        try {
            CALLBACK_RECORD_LIST.clear();
            openSsl.setNativeObjectLifecycleCallback(LifeCycleHookTest::callbackHandler);

            // Trigger an allocation and deallocation of a cipher
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                LibCtx.getInstance().fetchCipher("AES-256-GCM", null, confinedArena);
            }

            verifyAllocDealloc("EVP_CIPHER_fetch", "EVP_CIPHER_free");
        } finally {
            openSsl.clearNativeObjectLifecycleCallback();
        }
    }

    @Test
    public void allocDeallocCipherCallbackHandlerThrowsException() {
        PrintStream stderr = System.err;
        try {
            CALLBACK_RECORD_LIST.clear();
            openSsl.setNativeObjectLifecycleCallback(LifeCycleHookTest::callbackHandlerThrowsException);

            // Capture output to stderr
            ByteArrayOutputStream errStream = new ByteArrayOutputStream();
            System.setErr(new PrintStream(errStream, false, StandardCharsets.UTF_8));

            // Trigger an allocation and deallocation of a cipher
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                LibCtx.getInstance().fetchCipher("AES-256-GCM", null, confinedArena);
            }
            verifyAllocDealloc("EVP_CIPHER_fetch", "EVP_CIPHER_free");

            // Verify that the callback handler that throws an exception
            // was called and threw an exception that was caught and logged to stderr
            assertTrue(errStream.toString(StandardCharsets.UTF_8)
                    .contains("java.lang.RuntimeException: callbackHandlerThrowsException Failed"));
        } finally {
            System.setErr(stderr);
            openSsl.clearNativeObjectLifecycleCallback();
        }
    }

    // This test targets lifecycle hook code that addresses creating a new PKEY [isLifecycleNewPPkeyOut()]
    @Test
    public void allocateDeallocatePkey() {
        EVP_PKEY_CTX rsaCtx = libCtx.newPkeyCtx("RSA", null, testArena);
        rsaCtx.keygenInit();
        rsaCtx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_BITS, 2048)));
        try {
            CALLBACK_RECORD_LIST.clear();
            openSsl.setNativeObjectLifecycleCallback(LifeCycleHookTest::callbackHandler);

            // Trigger an allocation and deallocation of a PKEY
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                rsaCtx.generate(confinedArena);
            }

            verifyAllocDealloc("EVP_PKEY_generate", "EVP_PKEY_free");
        } finally {
            openSsl.clearNativeObjectLifecycleCallback();
        }
    }

    // This test verifies that if an allocation attempt fails no allocation event is recoded
    @Test
    public void allocatePkeyException() {
        EVP_PKEY_CTX rsaCtx = libCtx.newPkeyCtx("RSA", null, testArena);
        rsaCtx.keygenInit();
        rsaCtx.setParams(this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.ofUnsigned(EVP_PKEY.PKEY_PARAM_RSA_BITS, 512)));
        try {
            CALLBACK_RECORD_LIST.clear();
            openSsl.setNativeObjectLifecycleCallback(LifeCycleHookTest::callbackHandler);

            // Trigger an allocation that throws an exception
            try (OsslArena confinedArena = OsslArena.ofConfined()) {
                rsaCtx.generate(confinedArena);
                fail("Failed to throw OpenSslException:EVP_PKEY_generate failed");
            } catch (OpenSslException e) {
                assertTrue(e.getMessage().contains("EVP_PKEY_generate failed"));
            }

            // Verify expected native object allocation/deallocation events recorded
            assertEquals(0, CALLBACK_RECORD_LIST.size());
        } finally {
            openSsl.clearNativeObjectLifecycleCallback();
        }
    }

    // This test verifies that temporary memory allocated by randBytes() is allocated to be cleared when freed
    @Test
    public void randBytesUsesClearFree() {
        try {
            CALLBACK_RECORD_LIST.clear();
            openSsl.setNativeObjectLifecycleCallback(LifeCycleHookTest::callbackHandler);

            libCtx.randBytes(new byte[32], 256);

            verifyAllocDealloc("CRYPTO_malloc", "CRYPTO_clear_free");
        } finally {
            openSsl.clearNativeObjectLifecycleCallback();
        }
    }

    void verifyAllocDealloc(String allocFuncName, String deallocFuncName) {
        assertEquals(2, CALLBACK_RECORD_LIST.size());

        CallbackRecord alloc = CALLBACK_RECORD_LIST.get(0);
        CallbackRecord dealloc = CALLBACK_RECORD_LIST.get(CALLBACK_RECORD_LIST.size() - 1);

        assertEquals(NativeObjectLifecycleCallback.OpType.NEW, alloc.opType);
        assertEquals(allocFuncName, alloc.funcName);

        assertEquals(NativeObjectLifecycleCallback.OpType.FREE, dealloc.opType);
        assertEquals(deallocFuncName, dealloc.funcName);

        assertEquals(alloc.address, dealloc.address);
    }

    static public void callbackHandler(NativeObjectLifecycleCallback.OpType opType, String funcName, long address) {
        CALLBACK_RECORD_LIST.add(new CallbackRecord(opType, funcName, address));
    }

    static class CallbackRecord {
        NativeObjectLifecycleCallback.OpType opType;
        String funcName;
        long address;

        CallbackRecord(NativeObjectLifecycleCallback.OpType opType, String funcName, long address) {
            this.opType = opType;
            this.funcName = funcName;
            this.address = address;
        }
    }

    static public void callbackHandlerThrowsException(NativeObjectLifecycleCallback.OpType opType, String funcName, long address) {
        LifeCycleHookTest.callbackHandler(opType, funcName, address);
        throw new RuntimeException("callbackHandlerThrowsException Failed");
    }

}
