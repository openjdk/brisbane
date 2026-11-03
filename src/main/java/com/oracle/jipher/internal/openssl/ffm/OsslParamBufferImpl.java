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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.lang.invoke.MethodHandle;
import java.lang.ref.Reference;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import com.oracle.jipher.internal.openssl.OSSL_PARAM;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.OSSL_PARAM.EMPTY_ARRAY;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.constString;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_ALIGNMENT;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_SIZE;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.calcBufferMemoryRequirement;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.cleanseData;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.isEnd;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.load;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.setEnd;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.store;

public final class OsslParamBufferImpl implements OsslParamBuffer {

    static final OsslParamBuffer EMPTY_PARAM_BUFFER = new OsslParamBufferImpl();

    static final MethodHandle OSSL_PARAM_LOCATE_CONST_FUNC;
    static final MethodHandle OSSL_PARAM_FREE_FUNC;

    static {
        OSSL_PARAM_LOCATE_CONST_FUNC = downcallHandle(
                "OSSL_PARAM_locate_const", "(MM)M", LinkerOption.CRITICAL);
        OSSL_PARAM_FREE_FUNC = downcallHandle(
                "OSSL_PARAM_free", FREE_FUNCDESC);
    }

    final OSSL_PARAM[] params;
    OSSL_PARAM[] loadedParams;
    final boolean ephemeral;
    final long totalBufSize;
    final long totalSensitiveBufSize;
    final MemorySegment paramsSeg;
    final MemorySegment sensitiveDataSeg;
    final int paramCount;
    final boolean useReturnSize;
    final boolean readOnly;

    // Used for EMPTY_PARAM_BUFFER.
    private OsslParamBufferImpl() {
        this.params = null;
        this.ephemeral = false;
        this.totalBufSize = 0L;
        this.totalSensitiveBufSize = 0L;
        this.paramsSeg = MemorySegment.NULL;
        this.sensitiveDataSeg = MemorySegment.NULL;
        this.paramCount = 0;
        this.useReturnSize = false;
        this.readOnly = false;
    }

    // Used for EVP_*_gettable*_params, EVP_*_settable*_params and EVP_PKEY_todata.
    OsslParamBufferImpl(MemorySegment paramsSeg, int paramCount, boolean useReturnSize) {
        this.params = null;
        this.ephemeral = false;
        this.totalBufSize = 0L;
        this.totalSensitiveBufSize = 0L;
        this.paramsSeg = paramsSeg.asReadOnly();
        this.sensitiveDataSeg = MemorySegment.NULL;
        this.paramCount = paramCount;
        this.useReturnSize = useReturnSize;
        this.readOnly = true;
    }

    // Pre-allocated.
    // Used for EVP_CipherInit_ex2, EVP_PKEY_fromdata, EVP_KDF_derive, EVP_PKEY_*_init_ex, EVP_*_get_params, EVP_*_set_params, etc.
    OsslParamBufferImpl(OSSL_PARAM[] params, MemorySegment paramsSeg, MemorySegment sensitiveDataSeg, boolean useReturnSize) {
        this.params = params;
        this.ephemeral = false;
        this.totalBufSize = 0L;
        this.totalSensitiveBufSize = 0L;
        boolean readOnly = !useReturnSize;
        this.paramsSeg = readOnly ? paramsSeg.asReadOnly() : paramsSeg;
        this.sensitiveDataSeg = sensitiveDataSeg;
        this.paramCount = params.length;
        this.useReturnSize = useReturnSize;
        this.readOnly = readOnly;
    }

    // Allocated and stored on-demand.
    // Used for EVP_CipherInit_ex2, EVP_PKEY_fromdata, EVP_KDF_derive, EVP_PKEY_*_init_ex, EVP_*_get_params, EVP_*_set_params, etc.
    OsslParamBufferImpl(OSSL_PARAM[] params, long totalBufSize, long totalSensitiveBufSize, boolean useReturnSize) {
        this.params = params;
        this.ephemeral = true;
        this.totalBufSize = totalBufSize;
        this.totalSensitiveBufSize = totalSensitiveBufSize;
        this.paramsSeg = MemorySegment.NULL;
        this.sensitiveDataSeg = MemorySegment.NULL;
        this.paramCount = params.length;
        this.useReturnSize = useReturnSize;
        this.readOnly = !useReturnSize;
    }

    // This method is only used to free MemorySegments returned by EVP_PKEY_todata.
    static void osslParamFree(MemorySegment paramsSeg) {
        try {
            OSSL_PARAM_FREE_FUNC.invokeExact(paramsSeg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    // Only use this for private keypair exports returned by EVP_PKEY_todata(PKEY_KEYPAIR, ...).
    static void osslParamClearFree(MemorySegment paramsSeg) {
        try {
            // Iterate over the OSSL_PARAMs in paramsSeg before the END marker, and cleanse each owned
            // payload before OSSL_PARAM_free releases the allocation back to OpenSSL.
            long offset = 0L;
            while (!isEnd(paramsSeg, offset)) {
                cleanseData(paramsSeg, offset);
                offset += C_OSSL_PARAM_SIZE;
            }
        } finally {
            // Always free the OpenSSL-owned OSSL_PARAM structure, even if payload cleansing fails.
            osslParamFree(paramsSeg);
        }
    }

    // Used for EVP_*_gettable*_params and EVP_*_settable*_params.
    static OsslParamBuffer newReadOnlyTemplateParamBuffer(MemorySegment paramsSeg) {
        if (paramsSeg.address() == 0L) {
            return EMPTY_PARAM_BUFFER;
        }
        int paramCount = countParams(paramsSeg);
        long paramsSegSize = (paramCount + 1) * C_OSSL_PARAM_SIZE;
        return new OsslParamBufferImpl(paramsSeg.reinterpret(paramsSegSize), paramCount, true);
    }

    // Used for EVP_PKEY_todata.
    static OsslParamBuffer newDataParamBuffer(MemorySegment paramsSeg, Arena arena) {
        return newDataParamBuffer(paramsSeg, arena, false);
    }

    // Used for EVP_PKEY_todata.
    static OsslParamBuffer newDataParamBuffer(MemorySegment paramsSeg, Arena arena, boolean privateExport) {
        if (paramsSeg.address() == 0L) {
            return EMPTY_PARAM_BUFFER;
        }
        Consumer<MemorySegment> cleanup = privateExport
                ? OsslParamBufferImpl::osslParamClearFree
                : OsslParamBufferImpl::osslParamFree;

        boolean doCleanup = true;
        try {
            int paramCount = countParams(paramsSeg);
            long paramsSegSize = (paramCount + 1L) * C_OSSL_PARAM_SIZE;
            MemorySegment managedSeg = paramsSeg.reinterpret(paramsSegSize, arena, cleanup);

            doCleanup = false;
            return new OsslParamBufferImpl(managedSeg, paramCount, false);
        } finally {
            if (doCleanup) {
                cleanup.accept(paramsSeg);
            }
        }
    }

    // Used for EVP_CipherInit_ex2, EVP_PKEY_fromdata, EVP_KDF_derive, EVP_PKEY_*_init_ex, EVP_*_get_params, EVP_*_set_params, etc.
    static OsslParamBuffer newParamBuffer(OSSL_PARAM[] params, boolean useReturnSize, Arena arena) {
        // Determine the amount of memory that will need to be allocated for the
        // OSSL_PARAMs, including the END marker, and (separately) both the sensitive
        // and non-sensitive buffers they point to.
        int paramCount = 0;
        long totalBufSize = 0L;
        long totalSensitiveBufSize = 0L;
        for (OSSL_PARAM param : params) {
            ++paramCount;
            long bufSize = calcBufferMemoryRequirement(param);
            if (param.sensitive) {
                totalSensitiveBufSize = Math.addExact(totalSensitiveBufSize, bufSize);
            } else {
                totalBufSize = Math.addExact(totalBufSize, bufSize);
            }
        }
        totalBufSize += (paramCount + 1L) * C_OSSL_PARAM_SIZE;

        if (arena != null) {
            MemorySegment paramBufSeg = arena.allocate(totalBufSize, C_OSSL_PARAM_ALIGNMENT);
            MemorySegment sensitiveDataSeg = MemorySegment.NULL;
            if (totalSensitiveBufSize > 0L) {
                // Allocate a separate sliced heap for sensitive data that will be cleared when freed.
                sensitiveDataSeg = OpenSslAllocators.zallocClearFree(totalSensitiveBufSize, arena);
            }
            MemorySegment paramsSeg = storeParams(params, paramBufSeg, sensitiveDataSeg);
            return new OsslParamBufferImpl(params, paramsSeg, sensitiveDataSeg, useReturnSize);
        }
        return new OsslParamBufferImpl(params, totalBufSize, totalSensitiveBufSize, useReturnSize);
    }

    static void withTemplateParamsSegIfNotEmpty(OsslParamBuffer paramBuffer, Consumer<MemorySegment> consumer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, MemorySegment.NULL, consumer);
    }

    static void withTemplateParamsSegIfNotEmpty(OsslParamBuffer paramBuffer, MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        if (paramBuffer.count() > 0) {
            withTemplateParamsSeg(paramBuffer, scratchBuffer, consumer);
        }
    }

    static void withTemplateParamsSeg(OsslParamBuffer paramBuffer, MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        ((OsslParamBufferImpl) paramBuffer).withTemplateParamsSeg(scratchBuffer, consumer);
    }

    // Used for EVP_*_get_params.
    void withTemplateParamsSeg(MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        if (this.readOnly) {
            throw new IllegalArgumentException("Read-only OsslParamBuffer supplied");
        }
        if (!this.ephemeral) {
            resetReturnSizes(this.paramsSeg, this.paramCount);
            consumer.accept(this.paramsSeg);
        } else if (this.totalBufSize <= scratchBuffer.byteSize() && this.totalSensitiveBufSize == 0L) {
            // Fast path. A confined Arena is not required.
            MemorySegment ephParamsSeg = storeParams(this.params, scratchBuffer, MemorySegment.NULL);
            consumer.accept(ephParamsSeg);
            this.loadedParams = loadParams(this.params, ephParamsSeg, this.paramCount, this.useReturnSize);
            Reference.reachabilityFence(scratchBuffer);
        } else {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment paramBufSeg = this.totalBufSize <= scratchBuffer.byteSize() ?
                        scratchBuffer : arena.allocate(this.totalBufSize, C_OSSL_PARAM_ALIGNMENT);
                MemorySegment ephSensDataSeg = MemorySegment.NULL;
                if (this.totalSensitiveBufSize > 0L) {
                    // Allocate a separate sliced heap for sensitive data that will be cleared when freed.
                    ephSensDataSeg = OpenSslAllocators.zallocClearFree(this.totalSensitiveBufSize, arena);
                }
                MemorySegment ephParamsSeg = storeParams(this.params, paramBufSeg, ephSensDataSeg);
                consumer.accept(ephParamsSeg);
                this.loadedParams = loadParams(this.params, ephParamsSeg, this.paramCount, this.useReturnSize);
                Reference.reachabilityFence(scratchBuffer);
            }
        }
    }

    static void withDataParamsSegIfNotEmpty(OsslParamBuffer paramBuffer, Consumer<MemorySegment> consumer) {
        withDataParamsSegIfNotEmpty(paramBuffer, MemorySegment.NULL, consumer);
    }

    static void withDataParamsSeg(OsslParamBuffer paramBuffer, Consumer<MemorySegment> consumer) {
        withDataParamsSeg(paramBuffer, MemorySegment.NULL, consumer);
    }

    static void withDataParamsSegIfNotEmpty(OsslParamBuffer paramBuffer, MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        if (paramBuffer.count() > 0) {
            withDataParamsSeg(paramBuffer, scratchBuffer, consumer);
        }
    }

    static void withDataParamsSeg(OsslParamBuffer paramBuffer, MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        ((OsslParamBufferImpl) paramBuffer).withDataParamsSeg(scratchBuffer, consumer);
    }

    void withDataParamsSeg(MemorySegment scratchBuffer, Consumer<MemorySegment> consumer) {
        if (this.useReturnSize) {
            throw new IllegalArgumentException("OsslParamBuffer has no data");
        }
        if (!this.ephemeral) {
            consumer.accept(this.paramsSeg);
        } else if (this.totalBufSize <= scratchBuffer.byteSize() && this.totalSensitiveBufSize == 0L) {
            // Fast path. A confined Arena is not required.
            MemorySegment ephParamsSeg = storeParams(this.params, scratchBuffer, MemorySegment.NULL);
            consumer.accept(ephParamsSeg.asReadOnly());
        } else {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment paramBufSeg = this.totalBufSize <= scratchBuffer.byteSize() ?
                        scratchBuffer : arena.allocate(this.totalBufSize, C_OSSL_PARAM_ALIGNMENT);
                MemorySegment ephSensDataSeg = MemorySegment.NULL;
                if (this.totalSensitiveBufSize > 0L) {
                    // Allocate a separate sliced heap for sensitive data that will be cleared when freed.
                    ephSensDataSeg = OpenSslAllocators.zallocClearFree(this.totalSensitiveBufSize, arena);
                }
                MemorySegment ephParamsSeg = storeParams(this.params, paramBufSeg, ephSensDataSeg);
                consumer.accept(ephParamsSeg.asReadOnly());
            }
        }
    }

    static int countParams(MemorySegment paramsSeg) {
        // Count the number of OSSL_PARAMs in paramsSeg before the END marker.
        int paramCount = 0;
        long offset = 0L;
        while (!isEnd(paramsSeg, offset)) {
            ++paramCount;
            offset += C_OSSL_PARAM_SIZE;
        }
        return paramCount;
    }

    @Override
    public int count() {
        return this.paramCount;
    }

    @Override
    public OSSL_PARAM get(int index) {
        Objects.checkIndex(index, this.paramCount);
        OSSL_PARAM param;
        if (this.ephemeral) {
            param = (this.loadedParams != null) ? this.loadedParams[index] : this.params[index];
        } else if (this.params != null) {
            // Avoid having to load the key String of the OSSL_PARAM by providing the known key.
            param = load(this.params[index].key, this.paramsSeg, index * C_OSSL_PARAM_SIZE, this.useReturnSize);
        } else {
            param = load(this.paramsSeg, index * C_OSSL_PARAM_SIZE, this.useReturnSize);
        }

        // Ensure paramsSeg and sensitiveDataSeg remain reachable, via this, until all memory loading is
        // complete since keeping them reachable will also ensure that the original allocations that also
        // contain buffers that are pointed to by the data field in the OSSL_PARAM structure will not be
        // freed prematurely in the case where an ofAuto Arena was used.  The MemorySegment that contains
        // the pointer loaded from the data field will not itself ensure that paramsSeg and sensitiveDataSeg
        // remain reachable.
        // (Strictly speaking, keeping either of those reachable would be enough since they both hold
        // a reference to the common Arena Scope and keeping an ofAuto Arena reachable will keep all segments
        // allocated from it alive.)
        Reference.reachabilityFence(this);

        return param;
    }

    @Override
    public boolean hasKey(String key) {
        if (this.params != null) {
            return locateIndex(this.params, key) != -1;
        }
        return locateInternal(key).address() != 0L;
    }

    // Scan the params for a matching key to obtain the index, otherwise return -1.
    static int locateIndex(OSSL_PARAM[] params, String key) {
        for (int i = 0; i < params.length; ++i) {
            if (params[i].key.equals(key)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public Optional<OSSL_PARAM> locate(String key) {
        if (this.params != null) {
            int index = locateIndex(this.params, key);
            return index == -1 ? Optional.empty() : Optional.of(get(index));
        }

        MemorySegment osslParamSeg = locateInternal(key);
        if (osslParamSeg.address() == 0L) {
            return Optional.empty();
        }
        // Avoid having to load the key String of the OSSL_PARAM by providing the known key.
        OSSL_PARAM param = load(key, osslParamSeg.reinterpret(C_OSSL_PARAM_SIZE), 0L, this.useReturnSize);

        // Ensure paramsSeg and sensitiveDataSeg remain reachable, via this, until all memory loading is
        // complete since keeping them reachable will also ensure that the original allocations that also
        // contain buffers that are pointed to by the data field in the OSSL_PARAM structure will not be
        // freed prematurely in the case where an ofAuto Arena was used.  The MemorySegment that contains
        // the pointer loaded from the data field will not itself ensure that paramsSeg and sensitiveDataSeg
        // remain reachable.
        // (Strictly speaking, keeping either of those reachable would be enough since they both hold
        // a reference to the common Arena Scope and keeping an ofAuto Arena reachable will keep all segments
        // allocated from it alive.)
        Reference.reachabilityFence(this);

        return Optional.of(param);
    }

    MemorySegment locateInternal(String key) {
        if (this.paramCount == 0) {
            return MemorySegment.NULL;
        }
        try {
            return ((MemorySegment) OSSL_PARAM_LOCATE_CONST_FUNC.invokeExact(this.paramsSeg, constString(key))).asReadOnly();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OSSL_PARAM[] asArray() {
        if (this.paramCount == 0) {
            return EMPTY_ARRAY;
        }
        if (this.ephemeral) {
            return this.loadedParams != null ? this.loadedParams.clone() : this.params.clone();
        }
        OSSL_PARAM[] loadedParams;
        if (this.params != null) {
            // Avoid having to load the key String of each OSSL_PARAM.
            loadedParams = loadParams(this.params, this.paramsSeg, this.paramCount, this.useReturnSize);
        } else {
            loadedParams = loadParams(this.paramsSeg, this.paramCount, this.useReturnSize);
        }

        // Ensure paramSeg and sensitiveDataSeg remain reachable, via this, until all memory loading is
        // complete since keeping them reachable will also ensure that the original allocations that also
        // contain buffers that are pointed to by the data field in the OSSL_PARAM structure will not be
        // freed prematurely in the case where an ofAuto Arena was used.  The MemorySegment that contains
        // the pointer loaded from the data field will not itself ensure that paramSeg and sensitiveDataSeg
        // remain reachable.
        // (Strictly speaking, keeping either of those reachable would be enough since they both hold
        // a reference to the common Arena and keeping an ofAuto Arena reachable will keep all segments
        // allocated from it alive.)
        Reference.reachabilityFence(this);

        return loadedParams;
    }

    static MemorySegment storeParams(OSSL_PARAM[] params, MemorySegment paramBufSeg, MemorySegment sensitiveDataSeg) {
        SegmentAllocator allocator = SegmentAllocator.slicingAllocator(paramBufSeg);

        // Allocate the MemorySegment with space for the END marker.
        MemorySegment paramsSeg = allocator.allocate(C_OSSL_PARAM, params.length + 1);

        SegmentAllocator sensitiveAllocator = sensitiveDataSeg.byteSize() > 0L ? SegmentAllocator.slicingAllocator(sensitiveDataSeg) : null;
        storeParams(params, paramsSeg, allocator, sensitiveAllocator);
        return paramsSeg;
    }

    static void storeParams(OSSL_PARAM[] params, MemorySegment paramsSeg, SegmentAllocator allocator, SegmentAllocator sensitiveAllocator) {
        long offset = 0L;
        for (OSSL_PARAM param : params) {
            if (param != null) {
                store(param, paramsSeg, offset, (param.sensitive && param.dataSize != 0) ? sensitiveAllocator : allocator);
                offset += C_OSSL_PARAM_SIZE;
            }
        }
        setEnd(paramsSeg, offset);
    }

    // The caller must ensure that paramsSeg and all buffers pointed to by the data field of
    // OSSL_PARAM structures remain valid.  When an auto Arena was used to allocate the buffers,
    // The caller must ensure MemorySegments holding those buffers remain reachable.
    static OSSL_PARAM[] loadParams(OSSL_PARAM[] params, MemorySegment paramsSeg, int paramCount, boolean useReturnSize) {
        OSSL_PARAM[] loadedParams = new OSSL_PARAM[paramCount];
        long offset = 0L;
        for (int i = 0; i < paramCount; ++i) {
            // Avoid having to load the key String of the OSSL_PARAM by providing the known key.
            loadedParams[i] = load(params[i].key, paramsSeg, offset, useReturnSize);
            offset += C_OSSL_PARAM_SIZE;
        }
        return loadedParams;
    }

    // The caller must ensure that paramsSeg and all buffers pointed to by the data field of
    // OSSL_PARAM structures remain valid.  When an auto Arena was used to allocate the buffers,
    // The caller must ensure MemorySegments holding those buffers remain reachable.
    static OSSL_PARAM[] loadParams(MemorySegment paramsSeg, int paramCount, boolean useReturnSize) {
        OSSL_PARAM[] loadedParams = new OSSL_PARAM[paramCount];
        long offset = 0L;
        for (int i = 0; i < paramCount; ++i) {
            loadedParams[i] = load(paramsSeg, offset, useReturnSize);
            offset += C_OSSL_PARAM_SIZE;
        }
        return loadedParams;
    }

    static void resetReturnSizes(MemorySegment paramsSeg, int paramCount) {
        long offset = 0L;
        for (int i = 0; i < paramCount; ++i) {
            OsslParam.resetReturnSize(paramsSeg, offset);
            offset += C_OSSL_PARAM_SIZE;
        }
    }
}
