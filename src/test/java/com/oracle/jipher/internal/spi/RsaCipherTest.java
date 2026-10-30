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

import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

public class RsaCipherTest {

    private static final int OUTPUT_SIZE = 8;
    private static final byte FILL_VALUE = 0x55;

    private static byte[] filledBytes(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, FILL_VALUE);
        return bytes;
    }

    @Test
    public void doFinalFullOutput() throws Exception {
        byte[][] outputRef = new byte[1][];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return OUTPUT_SIZE;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset) {
                outputRef[0] = output;
                Arrays.fill(output, FILL_VALUE);
                return OUTPUT_SIZE;
            }
        };

        byte[] result = cipher.engineDoFinal(new byte[0], 0, 0);

        assertSame(outputRef[0], result);
        assertArrayEquals(filledBytes(OUTPUT_SIZE), result);
    }

    @Test
    public void doFinalShortOutput() throws Exception {
        final int shortOutputSize = OUTPUT_SIZE - 1;
        byte[][] outputRef = new byte[1][];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return OUTPUT_SIZE;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset) {
                outputRef[0] = output;
                Arrays.fill(output, FILL_VALUE);
                return shortOutputSize;
            }
        };

        byte[] result = cipher.engineDoFinal(new byte[0], 0, 0);

        // Short output is returned in a new buffer, leaving the output buffer to be cleared.
        assertNotSame(outputRef[0], result);
        assertArrayEquals(filledBytes(shortOutputSize), result);
        assertArrayEquals(new byte[OUTPUT_SIZE], outputRef[0]);
    }

    @Test
    public void doFinalBadPaddingNeg() throws Exception {
        BadPaddingException failure = new BadPaddingException();
        byte[][] outputRef = new byte[1][];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return OUTPUT_SIZE;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset)
                    throws BadPaddingException {
                outputRef[0] = output;
                Arrays.fill(output, FILL_VALUE);
                throw failure;
            }
        };

        try {
            cipher.engineDoFinal(new byte[0], 0, 0);
        } catch (BadPaddingException e) {
            assertSame(failure, e);
            assertArrayEquals(new byte[OUTPUT_SIZE], outputRef[0]);
            return;
        }

        fail("Expected BadPaddingException");
    }

    @Test
    public void doFinalIllegalBlockSizeNeg() throws Exception {
        IllegalBlockSizeException failure = new IllegalBlockSizeException();
        byte[][] outputRef = new byte[1][];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return OUTPUT_SIZE;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset)
                    throws IllegalBlockSizeException {
                outputRef[0] = output;
                Arrays.fill(output, FILL_VALUE);
                throw failure;
            }
        };

        try {
            cipher.engineDoFinal(new byte[0], 0, 0);
        } catch (IllegalBlockSizeException e) {
            assertSame(failure, e);
            assertArrayEquals(new byte[OUTPUT_SIZE], outputRef[0]);
            return;
        }

        fail("Expected IllegalBlockSizeException");
    }

    @Test
    public void doFinalShortBufferNeg() throws Exception {
        ShortBufferException failure = new ShortBufferException();
        byte[][] outputRef = new byte[1][];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return OUTPUT_SIZE;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset)
                    throws ShortBufferException {
                outputRef[0] = output;
                Arrays.fill(output, FILL_VALUE);
                throw failure;
            }
        };

        try {
            cipher.engineDoFinal(new byte[0], 0, 0);
        } catch (AssertionError e) {
            // ShortBufferException is unexpected in engineDoFinal so it is wrapped in an AssertionError.
            assertSame(failure, e.getCause());
            assertArrayEquals(new byte[OUTPUT_SIZE], outputRef[0]);
            return;
        }

        fail("Expected AssertionError");
    }
}
