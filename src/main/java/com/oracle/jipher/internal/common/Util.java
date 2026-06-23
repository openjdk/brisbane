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

package com.oracle.jipher.internal.common;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * A collection of utility methods for use within the provider.
 */
public final class Util {

    private Util() {
        // Do nothing
    }

    /**
     * Compute a hashcode for a byte array.
     * @param bytes the byte array
     * @return the computed hash-code
     */
    public static int hashCode(byte[] bytes) {
        if (bytes == null) {
            return 0;
        }
        int ret = bytes.length;
        for (byte b : bytes) {
            ret = (17 * ret) + b;
        }
        return ret;
    }

    /**
     * Returns whether the two arrays are equal.
     * <p>
     * If the given arrays are equal length, the comparison
     * is constant-time.
     * @param b1 the array to compare
     * @param b2 the array to compare
     * @return true iff b1 and b2 have the same contents
     */
    public static boolean equalsCT(byte[] b1, byte[] b2) {
        return MessageDigest.isEqual(b1, b2);
    }

    /**
     * Returns whether the two arrays are equal.
     * <p>
     * If the given arrays are equal length, the comparison
     * is constant-time.
     * @param c1 the array to compare
     * @param c2 tha array to compare
     * @return true iff c1 and c2 have the same contents
     */
    public static boolean equalsCT(char[] c1, char[] c2) {
        if (c1 == c2) return true;
        if (c1 == null || c2 == null) {
            return false;
        }
        if (c1.length != c2.length) {
            return false;
        }
        int result = 0;
        // constant-time comparison
        for (int i = 0; i < c1.length; i++) {
            result |= c1[i] ^ c2[i];
        }
        return result == 0;
    }

    /**
     * Converts a hexadecimal string to a byte[].
     *
     * @param hex a hexadecimal string
     * @return a byte[] representation of the hex string
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex string should contain even number of characters");
        }
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Converts a byte array to its hexadecimal string representation.
     * @param bytes the byte array to convert
     * @return the string containing the hex representation
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Overwrite the contents of byte arrays with zero bytes.
     * @param arrays the array containing the arrays to clear
     */
    public static void clearArrays(byte[]... arrays) {
        if (arrays != null) {
            for (byte[] array : arrays) {
                clearArray(array);
            }
        }
    }

    /**
     * Overwrite the contents of a byte array with zero bytes.
     * @param array the array to clear
     */
    public static void clearArray(byte[] array) {
        if (array != null) {
            Arrays.fill(array, (byte)0);
        }
    }

    /**
     * Overwrite the contents of a char array with zero chars.
     * @param array the array to clear
     */
    public static void clearArray(char[] array) {
        if (array != null) {
            Arrays.fill(array, (char)0);
        }
    }

    /**
     * Overwrite the contents of a long array with zero longs.
     * @param array the array to clear
     */
    public static void clearArray(long[] array) {
        if (array != null) {
            Arrays.fill(array, 0L);
        }
    }

    /**
     * Encodes the contents of the char array to a new byte array using the
     * specified character encoding.  Temporary copies are cleared in case the
     * string contains sensitive data that must be cleared, such as a password.
     *
     * @param charset the character encoding to use
     * @param chars the characters to be encoded
     * @param nulTerm if <code>true</code> then an ASCII NUL is appended unless
     * the last character in the char array is already a NUL
     * @return the encoded string in a new byte array
     */
    private static byte[] encodeString(Charset charset, char[] chars, boolean nulTerm) {
        CharsetEncoder encoder = charset.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        ByteBuffer bb = ByteBuffer.allocate((int)(encoder.maxBytesPerChar() * (chars.length + 1)) + 1);
        try {
            boolean nul = nulTerm && (chars.length == 0 || chars[chars.length - 1] != 0);
            CoderResult cr = encoder.encode(CharBuffer.wrap(chars), bb, !nul);
            if (cr.isUnderflow() && nul) {
                cr = encoder.encode(CharBuffer.wrap(new char[1]), bb, true);
            }
            if (cr.isUnderflow()) {
                cr = encoder.flush(bb);
            }
            if (!cr.isUnderflow()) {
                throw new InvalidParameterException("Unable to encode string: " + cr);
            }
            bb.flip();
            byte[] res = new byte[bb.remaining()];
            bb.get(res);
            return res;
        } finally {
            encoder.reset();
            clearArray(bb.array());
        }
    }

    /**
     * Encodes the contents of the char array to a UTF-8-encoded string in a
     * new byte array.  Temporary copies are cleared in case the string
     * contains sensitive data that must be cleared, such as a password.
     *
     * @param chars the characters to be encoded
     * @return the encoded string in a new byte array
     */
    public static byte[] utf8Encode(char[] chars) {
        return encodeString(StandardCharsets.UTF_8, chars, false);
    }

    /**
     * Encodes the contents of the char array to a UTF-16BE-encoded string in a
     * new byte array.  An ASCII NUL character is appended unless the last
     * character in the char array is already a NUL.  Temporary copies are
     * cleared in case the string contains sensitive data that must be cleared,
     * such as a password.
     *
     * @param chars the characters to be encoded
     * @return the encoded string in a new byte array
     */
    public static byte[] utf16BeEncode(char[] chars) {
        return encodeString(StandardCharsets.UTF_16BE, chars, true);
    }

    /**
     * Decodes the contents of the byte array to a new char array using the
     * specified character encoding.  Temporary copies are cleared in case the
     * string contains sensitive data that must be cleared, such as a password.
     *
     * @param charset the character encoding to use
     * @param bytes the bytes to be decoded
     * @param nulStrip if <code>true</code> then the last character is stripped
     * from the char array if it is an ASCII NUL
     * @return the decoded string in a new char array
     */
    private static char[] decodeString(Charset charset, byte[] bytes, boolean nulStrip) {
        CharsetDecoder decoder = charset.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        CharBuffer cb = CharBuffer.allocate((int)(decoder.maxCharsPerByte() * bytes.length) + 1);
        try {
            CoderResult cr = decoder.decode(ByteBuffer.wrap(bytes), cb, true);
            if (cr.isUnderflow()) {
                cr = decoder.flush(cb);
            }
            if (!cr.isUnderflow()) {
                throw new InvalidParameterException("Unable to decode string: " + cr);
            }
            cb.flip();
            if (nulStrip && cb.hasRemaining() && cb.get(cb.limit() - 1) == 0) {
                // Remove trailing nul
                cb.limit(cb.limit() - 1);
            }
            char[] res = new char[cb.remaining()];
            cb.get(res);
            return res;
        } finally {
            decoder.reset();
            clearArray(cb.array());
        }
    }

    /**
     * Decodes the UTF-8-encoded contents of the byte array to a string in a
     * new char array.  Temporary copies are cleared in case the string
     * contains sensitive data that must be cleared, such as a password.
     *
     * @param bytes the bytes to be decoded
     * @return the decoded string in a new char array
     */
    public static char[] utf8Decode(byte[] bytes) {
        return decodeString(StandardCharsets.UTF_8, bytes, false);
    }

    public static char[] asciiDecode(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; ++i) {
            chars[i] = (char)(bytes[i] & 0x7f);
        }
        return chars;
    }

    /**
     * Destroys a key if it is Destroyable.
     *
     * @param key the key to be destroyed
     */
    public static void destroyKey(Key key) {
        if (key instanceof Destroyable) {
            try {
                ((Destroyable)key).destroy();
            } catch (DestroyFailedException ex) {
                // Do nothing
            }
        }
    }

    /**
     * Returns the major component of the java.runtime.version
     *
     * @throws ParseException if the value of the system property java.runtime.version
     *         cannot be parsed to extract the major component
     * @return the major component of the java.runtime.version
     */
    public static int getJavaRuntimeMajorVersion() throws ParseException {
        String runtimeVersionString = ToolkitProperties.getJavaRuntimeVersionValue();
        int offset = runtimeVersionString.startsWith("1.") ? 2 : 0;
        Pattern pattern = Pattern.compile("^\\d+");
        Matcher matcher = pattern.matcher(runtimeVersionString.substring(offset));
        if (matcher.find()) {
            return Integer.parseInt(matcher.group());
        }
        throw new ParseException(runtimeVersionString, offset);
    }
}
