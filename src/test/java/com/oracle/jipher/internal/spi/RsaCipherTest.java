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

import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

public class RsaCipherTest {

    static class SecretKeyDummy implements SecretKey {

        private final byte[] key;
        private final String alg;

        private SecretKeyDummy(byte[] key, String alg) {
            this.alg = alg;
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return this.alg;
        }

        @Override
        public byte[] getEncoded() {
            return key;
        }

        public byte[] getKey() {
            return key;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }

    @Test
    public void doFinalShortBufferNeg() throws Exception {
        ShortBufferException shortBufferException = new ShortBufferException();
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            @Override
            protected int engineGetOutputSize(int inputLen) {
                return 1;
            }

            @Override
            protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset)
                    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
                throw shortBufferException;
            }
        };

        try {
            cipher.engineDoFinal(new byte[0], 0, 0);
        } catch (AssertionError e) {
            assertSame(shortBufferException, e.getCause());
            return;
        }

        fail("Expected AssertionError");
    }

    @Test
    public void wrapEncoding() throws Exception {
        byte[] encoding = new byte[] {1, 2, 3};
        byte[] wrapped = new byte[] {4, 5, 6};
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            {
                // Use reflection to mock RsaCipher initialization state.
                // This unit test only needs buffer.length as the configurable wrap input
                // capacity to exercise engineWrap, and does not need real RSA/OpenSSL
                // initialization.
                Field bufferField = RsaCipher.class.getDeclaredField("buffer");
                bufferField.setAccessible(true);
                bufferField.set(this, new byte[encoding.length]);
            }

            @Override
            protected byte[] engineDoFinal(byte[] input, int offset, int len) {
                return wrapped;
            }
        };

        assertSame(wrapped, cipher.engineWrap(new SecretKeyDummy(encoding, "AES")));

        assertArrayEquals(new byte[encoding.length], encoding);
    }

    @Test
    public void wrapNullEncodingNeg() throws Exception {
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {};

        try {
            cipher.engineWrap(new SecretKeyDummy(null, "AES"));
        } catch (InvalidKeyException e) {
            return;
        }

        fail("Expected InvalidKeyException");
    }

    @Test
    public void wrapEmptyEncodingNeg() throws Exception {
        byte[] encoding = new byte[0];
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {};

        try {
            cipher.engineWrap(new SecretKeyDummy(encoding, "AES"));
        } catch (InvalidKeyException e) {
            assertArrayEquals(new byte[0], encoding);
            return;
        }

        fail("Expected InvalidKeyException");
    }

    @Test
    public void wrapTooLongEncodingNeg() throws Exception {
        byte[] encoding = new byte[] {1, 2, 3};
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            {
                // Use reflection to mock RsaCipher initialization state.
                // This unit test only needs buffer.length as the configurable wrap input
                // capacity to exercise engineWrap, and does not need real RSA/OpenSSL
                // initialization.
                Field bufferField = RsaCipher.class.getDeclaredField("buffer");
                bufferField.setAccessible(true);
                bufferField.set(this, new byte[encoding.length - 1]);
            }
        };

        try {
            cipher.engineWrap(new SecretKeyDummy(encoding, "AES"));
        } catch (InvalidKeyException e) {
            assertArrayEquals(new byte[encoding.length], encoding);
            return;
        }

        fail("Expected InvalidKeyException");
    }

    @Test
    public void wrapFailureEncodingNeg() throws Exception {
        byte[] encoding = new byte[] {1, 2, 3};
        IllegalBlockSizeException failure = new IllegalBlockSizeException();
        RsaCipher cipher = new RsaCipher(RsaCipherPadding.OAEP) {
            {
                // Use reflection to mock RsaCipher initialization state.
                // This unit test only needs buffer.length as the configurable wrap input
                // capacity to exercise engineWrap, and does not need real RSA/OpenSSL
                // initialization.
                Field bufferField = RsaCipher.class.getDeclaredField("buffer");
                bufferField.setAccessible(true);
                bufferField.set(this, new byte[encoding.length]);
            }

            @Override
            protected byte[] engineDoFinal(byte[] input, int offset, int len)
                    throws IllegalBlockSizeException {
                throw failure;
            }
        };

        try {
            cipher.engineWrap(new SecretKeyDummy(encoding, "AES"));
        } catch (IllegalBlockSizeException e) {
            assertSame(failure, e);
            assertArrayEquals(new byte[encoding.length], encoding);
            return;
        }

        fail("Expected IllegalBlockSizeException");
    }
}
