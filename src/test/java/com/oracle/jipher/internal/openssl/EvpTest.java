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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

public abstract class EvpTest {

    protected OpenSsl openSsl;
    protected OSSL_LIB_CTX libCtx;
    protected OsslArena testArena;

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
}
