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

package com.oracle.jipher.internal.openssl.ffm;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

import org.junit.Test;

import com.oracle.jipher.internal.openssl.EvpTest;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER.GCM_IV_MAX_SIZE;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER.MAX_BLOCK_LENGTH;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER.MAX_KEY_LENGTH;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.ENCRYPTION;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class EvpCipherCtxTest extends EvpTest {

    @Test
    public void initClearsKeyAndIvScratch() {
        EvpCipherCtx ctx = (EvpCipherCtx) openSsl.newEvpCipherCtx(testArena);
        ctx.init(libCtx.fetchCipher("AES-256-GCM", null, testArena),
                filledBytes(32, 0x11),
                filledBytes(12, 0x22),
                ENCRYPTION);

        assertScratchCleared(ctx);
    }

    @Test
    public void initClearsKeyAndIvScratchNeg() {
        EvpCipherCtx ctx = (EvpCipherCtx) openSsl.newEvpCipherCtx(testArena);

        assertThrows(IllegalArgumentException.class,
                () -> ctx.init(libCtx.fetchCipher("AES-256-GCM", null, testArena),
                        filledBytes(32, 0x33),
                        filledBytes(GCM_IV_MAX_SIZE + 1, 0x44),
                        ENCRYPTION));

        assertScratchCleared(ctx);
    }

    private static void assertScratchCleared(EvpCipherCtx ctx) {
        long maxKeyOrBlockBufSize = Math.max(MAX_KEY_LENGTH, MAX_BLOCK_LENGTH);
        assertTrue(isZero(ctx.keyBufPA.allocate(maxKeyOrBlockBufSize)));
        assertTrue(isZero(ctx.ivBufPA.allocate(GCM_IV_MAX_SIZE)));
    }

    private static boolean isZero(MemorySegment segment) {
        for (long i = 0L; i < segment.byteSize(); i++) {
            if (segment.get(ValueLayout.JAVA_BYTE, i) != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] filledBytes(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
