/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any patent rights owned or freely
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

package com.oracle.jipher.internal.openssl.ffm;

import java.lang.foreign.MemorySegment;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jipher.internal.openssl.OSSL_PARAM;
import com.oracle.jipher.internal.openssl.OpenSsl;

import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_SIZE;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.setEnd;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.store;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.junit.Assert.assertArrayEquals;

public class OsslParamBufferImplTest {

    OpenSsl openSsl;

    @Before
    public void setUp() {
        openSsl = OpenSsl.getInstance();
    }

    @After
    public void verifyErrorQueueEmpty() {
        // Detect if the test has left an error on the thread's OpenSSL error queue, which might indicate a bug
        // either in the test or in the adapter layer.  It is important that errors inadvertently set in one
        // test are not reported in another.
        // Some OpenSSL API calls, in particular those on an uninitialised context, can add an error to the
        // thread's OpenSSL error queue but not return an error return code from the API call.  As the API call
        // does not return an error return code, an OpenSSL Exception, that would clear the thread's OpenSSL
        // error queue, isn't built and thrown.
        if (openSsl.peekLastError() != 0) {
            StringBuilder exMsg = new StringBuilder("OpenSSL error queue:");
            openSsl.forEachError(errorString -> exMsg.append('\n').append(errorString));
            Assert.fail(exMsg.toString());
        }
    }

    @Test
    public void osslParamClearFreeCleansesPayloadBeforeFree() {
        long paramsSize = 2L * C_OSSL_PARAM_SIZE;
        long payloadSize = 32L;
        MemorySegment paramsSeg = OpenSslAllocators.malloc(paramsSize).reinterpret(paramsSize);
        MemorySegment payloadSeg = OpenSslAllocators.malloc(payloadSize).reinterpret(payloadSize);

        try {
            paramsSeg.fill((byte) 0);
            payloadSeg.fill((byte) 0x5a);
            OSSL_PARAM param = OSSL_PARAM.of("test-key", new byte[(int) payloadSize]);

            // Use a fixed-segment allocator so that store() points the OSSL_PARAM data field at
            // payloadSeg, allowing the cleanup path to be verified directly here.
            store(param, paramsSeg, 0L, (byteSize, byteAlignment) -> payloadSeg);
            setEnd(paramsSeg, C_OSSL_PARAM_SIZE);

            OsslParamBufferImpl.osslParamClearFree(paramsSeg);

            assertArrayEquals(new byte[(int) payloadSize], payloadSeg.toArray(JAVA_BYTE));
        } finally {
            OpenSslAllocators.free(payloadSeg);
        }
    }
}
