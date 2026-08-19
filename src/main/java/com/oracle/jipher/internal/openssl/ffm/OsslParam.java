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

import java.lang.foreign.AddressLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.oracle.jipher.internal.openssl.OSSL_PARAM;

import static com.oracle.jipher.internal.openssl.OSSL_PARAM.PARAM_UNMODIFIED;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.Type;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_INT;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_POINTER;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_POINTER_UNBOUNDED;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_SIZE_T;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.UNBOUNDED_MAX;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.constString;
import static java.lang.Math.toIntExact;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG_UNALIGNED;

final class OsslParam {

    static final MemoryLayout C_OSSL_PARAM = MemoryLayout.structLayout(
            C_POINTER_UNBOUNDED.withName("key"),
            C_INT.withName("data_type"),
            MemoryLayout.paddingLayout(4),
            C_POINTER_UNBOUNDED.withName("data"),
            C_SIZE_T.withName("data_size"),
            C_SIZE_T.withName("return_size")
    ).withName("ossl_param_st");
    static final long C_OSSL_PARAM_SIZE = C_OSSL_PARAM.byteSize();
    static final long C_OSSL_PARAM_ALIGNMENT = C_OSSL_PARAM.byteAlignment();
    static final MemoryLayout C_OSSL_PARAM_SEQUENCE = MemoryLayout.sequenceLayout(UNBOUNDED_MAX / C_OSSL_PARAM.byteSize(), C_OSSL_PARAM);
    static final AddressLayout C_OSSL_PARAM_SEQUENCE_PTR = C_POINTER.withTargetLayout(C_OSSL_PARAM_SEQUENCE); // 'P'

    static final VarHandle OSSL_PARAM_KEY_HANDLE =
            C_OSSL_PARAM.varHandle(groupElement("key"));
    static final VarHandle OSSL_PARAM_DATA_TYPE_HANDLE =
            C_OSSL_PARAM.varHandle(groupElement("data_type"));
    static final VarHandle OSSL_PARAM_DATA_HANDLE =
            C_OSSL_PARAM.varHandle(groupElement("data"));
    static final VarHandle OSSL_PARAM_DATA_SIZE_HANDLE =
            C_OSSL_PARAM.varHandle(groupElement("data_size"));
    static final VarHandle OSSL_PARAM_RETURN_SIZE_HANDLE =
            C_OSSL_PARAM.varHandle(groupElement("return_size"));

    static final VarHandle BYTE_ARRAY_LONG_ACCESS_BE_HANDLE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    static void store(OSSL_PARAM param, MemorySegment paramSeg, long offset, SegmentAllocator allocator) {
        MemorySegment dataSeg;
        if (param.data != null) {
            checkDataSize(param);
            dataSeg = switch (param.dataType) {
                case NONE, UTF8_PTR, OCTET_PTR -> throw new AssertionError();
                case INTEGER, UNSIGNED_INTEGER, REAL -> storeNumber(param.data, allocator);
                case UTF8_STRING -> storeUtf8String(param.data, allocator);
                case OCTET_STRING -> allocator.allocateFrom(JAVA_BYTE, param.data);
            };
        } else {
            dataSeg = switch (param.dataType) {
                case UTF8_PTR, OCTET_PTR -> allocator.allocate(C_POINTER);
                default -> allocator.allocate(param.dataSize, Long.BYTES);
            };
        }

        OSSL_PARAM_KEY_HANDLE.set(paramSeg, offset, constString(param.key));
        OSSL_PARAM_DATA_TYPE_HANDLE.set(paramSeg, offset, param.dataType.ordinal());
        OSSL_PARAM_DATA_HANDLE.set(paramSeg, offset, dataSeg);
        OSSL_PARAM_DATA_SIZE_HANDLE.set(paramSeg, offset, param.dataSize);
        OSSL_PARAM_RETURN_SIZE_HANDLE.set(paramSeg, offset, PARAM_UNMODIFIED);
    }

    static long calcBufferMemoryRequirement(OSSL_PARAM param) {
        long size = 0L;
        if (param.key != null) {
            if (param.data != null) {
                checkDataSize(param);
                size = switch (param.dataType) {
                    case INTEGER, UNSIGNED_INTEGER, REAL -> param.dataSize + Long.BYTES - 1L;
                    case UTF8_STRING -> param.dataSize + 1L;
                    case OCTET_STRING -> param.dataSize;
                    case NONE, UTF8_PTR, OCTET_PTR -> throw new AssertionError();
                };
            } else {
                size = switch (param.dataType) {
                    case UTF8_PTR, OCTET_PTR -> C_POINTER.byteSize() + C_POINTER.byteAlignment() - 1;
                    default -> Math.addExact(param.dataSize, Long.BYTES - 1);
                };
            }
        }
        return size;
    }

    // This should only be called when param.data != null.
    static void checkDataSize(OSSL_PARAM param) {
        if (param.dataSize != param.data.length) {
            throw new IllegalArgumentException("OSSL_PARAM dataSize (" + param.dataSize + ") is not equal to data buffer size (" + param.data.length + ")");
        }
    }

    static MemorySegment storeNumber(byte[] data, SegmentAllocator allocator) {
        MemorySegment dataSeg = allocator.allocate(data.length, Long.BYTES);
        if (ByteOrder.nativeOrder() != ByteOrder.BIG_ENDIAN) {
            // Current platform is little-endian while BigInteger always uses big-endian.
            // Reverse the encoding. Truncate or pad on the right.
            storeReversed(data, dataSeg, data.length);
        } else {
            // Current platform is big-endian, the same byte order that BigInteger uses.
            MemorySegment.copy(data, 0, dataSeg, JAVA_BYTE, 0L, data.length);
        }
        return dataSeg;
    }

    static void storeReversed(byte[] src, MemorySegment dst, int len) {
        int sOff = len;
        long dOff = 0L;
        while (len >= Long.BYTES) {
            sOff -= Long.BYTES;
            // Storing with an unaligned ValueLayout benchmarks as faster than an 8-byte aligned
            // ValueLayout even though all stores will be aligned.
            dst.set(JAVA_LONG_UNALIGNED, dOff, (long) BYTE_ARRAY_LONG_ACCESS_BE_HANDLE.get(src, sOff));
            dOff += Long.BYTES;
            len -= Long.BYTES;
        }
        while (len-- > 0) {
            dst.set(JAVA_BYTE, dOff++, src[--sOff]);
        }
    }

    // For a UTF8_STRING, dataSize is set to the length of the NUL terminated C-string,
    // not counting the terminating NUL byte.
    // See the OpenSSL OSSL_PARAM documentation (https://docs.openssl.org/3.0/man3/OSSL_PARAM/#description).
    static MemorySegment storeUtf8String(byte[] data, SegmentAllocator allocator) {
        // Allocate the native buffer with additional space for the terminating NUL byte
        MemorySegment dataSeg = allocator.allocate(((long) data.length) + 1L);
        MemorySegment.copy(data, 0, dataSeg, JAVA_BYTE, 0L, data.length);
        dataSeg.set(JAVA_BYTE, data.length, (byte) 0); // NUL terminator
        return dataSeg;
    }

    static void resetReturnSize(MemorySegment paramSeg, long offset) {
        OSSL_PARAM_RETURN_SIZE_HANDLE.set(paramSeg, offset, PARAM_UNMODIFIED);
    }

    static void setEnd(MemorySegment paramSeg, long offset) {
        OSSL_PARAM_KEY_HANDLE.set(paramSeg, offset, MemorySegment.NULL);
        OSSL_PARAM_DATA_TYPE_HANDLE.set(paramSeg, offset, 0);
        OSSL_PARAM_DATA_HANDLE.set(paramSeg, offset, MemorySegment.NULL);
        OSSL_PARAM_DATA_SIZE_HANDLE.set(paramSeg, offset, 0L);
        OSSL_PARAM_RETURN_SIZE_HANDLE.set(paramSeg, offset, 0L);
    }

    static boolean isEnd(MemorySegment paramSeg, long offset) {
        MemorySegment keySeg = (MemorySegment) OSSL_PARAM_KEY_HANDLE.get(paramSeg, offset);
        return keySeg.address() == 0L;
    }

    static void cleanseData(MemorySegment paramSeg, long offset) {
        MemorySegment dataSeg = (MemorySegment) OSSL_PARAM_DATA_HANDLE.get(paramSeg, offset);
        long dataSize = (long) OSSL_PARAM_DATA_SIZE_HANDLE.get(paramSeg, offset);
        if (dataSeg.address() != 0L && dataSize > 0L && dataSize <= UNBOUNDED_MAX) {
            MemorySegment payloadSeg = dataSeg.reinterpret(dataSize);
            payloadSeg.fill((byte) 0);
        }
    }

    static OSSL_PARAM load(MemorySegment paramSeg, long offset, boolean useReturnSize) {
        MemorySegment keySeg = (MemorySegment) OSSL_PARAM_KEY_HANDLE.get(paramSeg, offset);
        String key = keySeg.getString(0L);
        return load(key, paramSeg, offset, useReturnSize);
    }

    static OSSL_PARAM load(String key, MemorySegment paramSeg, long offset, boolean useReturnSize) {
        Type dataType = Type.values()[(int) OSSL_PARAM_DATA_TYPE_HANDLE.get(paramSeg, offset)];
        long dataSize = (long) OSSL_PARAM_DATA_SIZE_HANDLE.get(paramSeg, offset);
        long returnSize = (long) OSSL_PARAM_RETURN_SIZE_HANDLE.get(paramSeg, offset);
        MemorySegment dataSeg = (MemorySegment) OSSL_PARAM_DATA_HANDLE.get(paramSeg, offset);
        if (!useReturnSize || returnSize != PARAM_UNMODIFIED) {
            if ((dataType == Type.UTF8_PTR || dataType == Type.OCTET_PTR) && dataSeg.address() != 0L) {
                // Dereference the pointer.
                dataSeg = dataSeg.get(C_POINTER_UNBOUNDED, 0L);
            }
            if (dataSeg.address() != 0L) {
                dataSeg = dataSeg.asSlice(0L, useReturnSize ? returnSize : dataSize);
                byte[] data = switch (dataType) {
                    case NONE -> throw new AssertionError();
                    case INTEGER, UNSIGNED_INTEGER, REAL -> loadNumber(dataSeg);
                    case UTF8_STRING, UTF8_PTR, OCTET_STRING, OCTET_PTR -> dataSeg.toArray(JAVA_BYTE);
                };
                return OSSL_PARAM.of(key, dataType, data, returnSize);
            }
        }
        return OSSL_PARAM.of(key, dataType, dataSize, returnSize);
    }

    static byte[] loadNumber(MemorySegment dataSeg) {
        byte[] bytes;
        if (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN) {
            bytes = dataSeg.toArray(JAVA_BYTE);
        } else {
            // Current platform is little-endian. Reverse the encoding.
            bytes = new byte[toIntExact(dataSeg.byteSize())];
            loadReversed(dataSeg, bytes, bytes.length);
        }
        return bytes;
    }

    static void loadReversed(MemorySegment src, byte[] dst, int len) {
        long sOff = 0L;
        int dOff = len;
        while (len >= Long.BYTES) {
            dOff -= Long.BYTES;
            // Loading with an unaligned ValueLayout benchmarks as faster than an 8-byte aligned
            // ValueLayout even though all loads will be aligned.
            BYTE_ARRAY_LONG_ACCESS_BE_HANDLE.set(dst, dOff, src.get(JAVA_LONG_UNALIGNED, sOff));
            sOff += Long.BYTES;
            len -= Long.BYTES;
        }
        while (len-- > 0) {
            dst[--dOff] = src.get(JAVA_BYTE, sOff++);
        }
    }

}
