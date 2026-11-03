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
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.Optional;
import javax.crypto.ShortBufferException;

import com.oracle.jipher.internal.openssl.EVP_CIPHER;
import com.oracle.jipher.internal.openssl.EVP_CIPHER.Mode;
import com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX;
import com.oracle.jipher.internal.openssl.OSSL_PARAM;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.EVP_CIPHER.CIPHER_PARAM_PADDING;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER.GCM_IV_MAX_SIZE;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER.MAX_BLOCK_LENGTH;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER.MAX_KEY_LENGTH;
import static com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX.Enc.NO_CHANGE;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.BOOL_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.COPY_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_INT;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.INT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.HEAP_ACCESS;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PTR_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.TTSP_MAX_DATA;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.allocateFromNullable;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegment;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_ALIGNMENT;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.EMPTY_PARAM_BUFFER;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;
import static java.lang.Math.toIntExact;

final class EvpCipherCtx extends PoolableObjectBase<EvpCipherCtx> implements EVP_CIPHER_CTX {

    static final long UNKNOWN = -1L;

    // EVP_CipherUpdate uses a (signed) int (instead of a size_t) to specify the length of the input in bytes.
    // Consequently, the maximum length of an input in bytes passed to update must be Integer.MAX_VALUE or less.
    // The value used here is the largest power of 2 <= Integer.MAX_VALUE.
    static final long MAX_UPDATE_CHUNK_SIZE = 0x40000000L; // 1 GiB

    static final long PARAM_BUFFER_SIZE = 128L;

    static final ObjectPool<EvpCipherCtx> CIPHER_CTX_OBJECT_POOL = new ObjectPool<>();

    static final MethodHandle EVP_CIPHER_CTX_NEW_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_COPY_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_RESET_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET0_CIPHER_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET_BLOCK_SIZE_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET_KEY_LENGTH_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET_IV_LENGTH_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_GET_TAG_LENGTH_FUNC;
    static final MethodHandle EVP_CIPHER_INIT_EX2_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_IS_ENCRYPTING_FUNC;
    static final MethodHandle EVP_CIPHER_UPDATE_FUNC;
    static final MethodHandle EVP_CIPHER_UPDATE_HEAP_FUNC;
    static final MethodHandle EVP_CIPHER_FINAL_EX_FUNC;
    static final MethodHandle EVP_CIPHER_CTX_FREE_FUNC;

    static {
        EVP_CIPHER_CTX_NEW_FUNC = downcallHandleCheckNull(
                "EVP_CIPHER_CTX_new", NEW_FUNCDESC);
        EVP_CIPHER_CTX_COPY_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_CTX_copy", COPY_FUNCDESC);
        EVP_CIPHER_CTX_RESET_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_CTX_reset", INT_FUNCDESC);
        EVP_CIPHER_CTX_GET0_CIPHER_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_get0_cipher", PTR_FUNCDESC, CRITICAL);
        EVP_CIPHER_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_CIPHER_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_CIPHER_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_CTX_get_params", PARAMS_FUNCDESC);
        EVP_CIPHER_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_CTX_set_params", PARAMS_FUNCDESC);
        EVP_CIPHER_CTX_GET_BLOCK_SIZE_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_get_block_size", INT_FUNCDESC, CRITICAL);
        EVP_CIPHER_CTX_GET_KEY_LENGTH_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_get_key_length", INT_FUNCDESC);
        EVP_CIPHER_CTX_GET_IV_LENGTH_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_get_iv_length", INT_FUNCDESC);
        EVP_CIPHER_CTX_GET_TAG_LENGTH_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_get_tag_length", INT_FUNCDESC);
        EVP_CIPHER_INIT_EX2_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CipherInit_ex2", "(MMMMIM)I");
        EVP_CIPHER_CTX_IS_ENCRYPTING_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_is_encrypting", BOOL_FUNCDESC, CRITICAL);
        EVP_CIPHER_UPDATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CipherUpdate", "(MMMMI)I");
        EVP_CIPHER_UPDATE_HEAP_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CipherUpdate", "(MMMMI)I", HEAP_ACCESS);
        EVP_CIPHER_FINAL_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CipherFinal_ex", "(MMM)I");
        EVP_CIPHER_CTX_FREE_FUNC = downcallHandle(
                "EVP_CIPHER_CTX_free", FREE_FUNCDESC);
    }

    final MemorySegment evpCipherCtx;
    final boolean releaseToPool;
    final MemorySegment scratchBufSeg;
    final MemorySegment paramBufSeg;
    final SegmentAllocator keyBufPA; // Prefix allocator for key buffers.
    final SegmentAllocator blockBufPA; // Prefix allocator for block buffers.
    final SegmentAllocator ivBufPA; // Prefix allocator for IV buffers.
    final MemorySegment outLenSeg;
    Mode mode;
    long bufferedBytes;
    // The following setting is only meaningful for cipher contexts that have been initialised with a cipher that
    // supports padding - i.e. those with ECB or CBC mode.  It is not meaningful for cipher context's that have
    // not been initialised or have been reset but not re-initialised.
    boolean paddingEnabled;

    EvpCipherCtx(boolean releaseToPool, Arena arena) {
        MemorySegment evpCipherCtx;
        try {
            evpCipherCtx = (MemorySegment) EVP_CIPHER_CTX_NEW_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.evpCipherCtx = evpCipherCtx.reinterpret(arena, EvpCipherCtx::free);
        this.releaseToPool = releaseToPool;

        long maxKeyOrBlockBufSize = Math.max(MAX_KEY_LENGTH, MAX_BLOCK_LENGTH);
        long scratchBufSize = PARAM_BUFFER_SIZE + maxKeyOrBlockBufSize + GCM_IV_MAX_SIZE + C_INT.byteSize();
        this.scratchBufSeg = arena.allocate(scratchBufSize, C_OSSL_PARAM_ALIGNMENT);
        SegmentAllocator allocator = SegmentAllocator.slicingAllocator(this.scratchBufSeg);
        this.paramBufSeg = allocator.allocate(PARAM_BUFFER_SIZE, C_OSSL_PARAM_ALIGNMENT);
        // key and block buffers overlap since no method uses both.
        SegmentAllocator keyBlockPA = SegmentAllocator.prefixAllocator(allocator.allocate(maxKeyOrBlockBufSize));
        this.keyBufPA = keyBlockPA;
        this.blockBufPA = keyBlockPA;
        this.ivBufPA = SegmentAllocator.prefixAllocator(allocator.allocate(GCM_IV_MAX_SIZE));
        this.outLenSeg = allocator.allocate(C_INT);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_CIPHER_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static EvpCipherCtx getEvpCipherCtxAutoArena() {
        return CIPHER_CTX_OBJECT_POOL.pop().orElseGet(() -> new EvpCipherCtx(true, Arena.ofAuto()));
    }

    @Override
    public void release() {
        // Clear any sensitive data.
        reset();

        if (releaseToPool) {
            CIPHER_CTX_OBJECT_POOL.push(this);
        }
    }

    @Override
    public EVP_CIPHER_CTX dup(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        EvpCipherCtx dupCtx = new EvpCipherCtx(false, arena);
        dupCtx.copy(this);
        return dupCtx;
    }

    @Override
    public EVP_CIPHER_CTX dup() {
        EvpCipherCtx dupCtx = getEvpCipherCtxAutoArena();
        dupCtx.copy(this);
        return dupCtx;
    }

    void copy(EvpCipherCtx ctx) {
        try {
            EVP_CIPHER_CTX_COPY_FUNC.invokeExact(this.evpCipherCtx, ctx.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.mode = ctx.mode;
        this.bufferedBytes = ctx.bufferedBytes;
        this.paddingEnabled = ctx.paddingEnabled;
    }

    @Override
    public void reset() {
        try {
            EVP_CIPHER_CTX_RESET_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.mode = null;
        this.bufferedBytes = 0L;
    }

    @Override
    public boolean isInitialized() {
        MemorySegment cipherSeg;
        try {
            cipherSeg = (MemorySegment) EVP_CIPHER_CTX_GET0_CIPHER_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return cipherSeg.address() != 0L;
    }

    @Override
    public OsslParamBuffer gettableParams() {
        if (!isInitialized()) {
            // Unlike some other EVP_*_gettable_params calls, EVP_CIPHER_CTX_gettable_params will
            // cause a segfault if the EVP_CIPHER_CTX has not been initialized with an EVP_CIPHER.
            // Return an empty OsslParamBuffer in this case, for consistency with other similar APIs.
            return EMPTY_PARAM_BUFFER;
        }
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_CIPHER_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpCipherCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        if (!isInitialized()) {
            // Unlike some other EVP_*_settable_params calls, EVP_CIPHER_CTX_settable_params will
            // cause a segfault if the EVP_CIPHER_CTX has not been initialized with an EVP_CIPHER.
            // Return an empty OsslParamBuffer in this case, for consistency with other similar APIs.
            return EMPTY_PARAM_BUFFER;
        }
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_CIPHER_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpCipherCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        // Use the whole of scratchBufSeg, rather than just paramBufferSeg, since no other slices are in use.
        withTemplateParamsSegIfNotEmpty(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
            try {
                EVP_CIPHER_CTX_GET_PARAMS_FUNC.invokeExact(this.evpCipherCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        if (paramBuffer.count() > 0) {
            // Use the whole of scratchBufSeg, rather than just paramBufferSeg, since no other slices are in use.
            withDataParamsSeg(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
                try {
                    EVP_CIPHER_CTX_SET_PARAMS_FUNC.invokeExact(this.evpCipherCtx, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });

            if (this.mode == Mode.ECB || this.mode == Mode.CBC) {
                paramBuffer.locate(CIPHER_PARAM_PADDING).ifPresent(p -> this.paddingEnabled = p.intValue() != 0);
            }
        }
    }

    @Override
    public int blockSize() {
        if (!isInitialized()) {
            // In some OpenSSL versions an uninitialized EVP_CIPHER_CTX will result in
            // a SIGSEGV due to NULL pointer dereference in EVP_CIPHER_CTX_get_block_size.
            // Additional NULL checks were added in https://github.com/openssl/openssl/commit/6f22bcd631a
            return 0;
        }
        try {
            return (int) EVP_CIPHER_CTX_GET_BLOCK_SIZE_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int keyLength() {
        if (!isInitialized()) {
            // In some OpenSSL versions an uninitialized EVP_CIPHER_CTX will result in
            // a SIGSEGV due to NULL pointer dereference in EVP_CIPHER_CTX_get_key_length.
            // Additional NULL checks were added in https://github.com/openssl/openssl/commit/6f22bcd631a
            return 0;
        }
        try {
            return (int) EVP_CIPHER_CTX_GET_KEY_LENGTH_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int ivLength() {
        if (!isInitialized()) {
            // In some OpenSSL versions an uninitialized EVP_CIPHER_CTX will result in
            // a SIGSEGV due to NULL pointer dereference in EVP_CIPHER_CTX_get_iv_length.
            // Additional NULL checks were added in https://github.com/openssl/openssl/commit/6f22bcd631a
            return 0;
        }
        try {
            return (int) EVP_CIPHER_CTX_GET_IV_LENGTH_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int tagLength() {
        try {
            return (int) EVP_CIPHER_CTX_GET_TAG_LENGTH_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void init(EVP_CIPHER type, byte[] key, byte[] iv, Enc enc, OsslParamBuffer paramBuffer) {
        init((EvpCipher) type, key, iv, enc, paramBuffer);
    }

    void init(EvpCipher type, byte[] key, byte[] iv, Enc enc, OsslParamBuffer paramBuffer) {
        int requiredKeyLength;
        int requiredIvLength;
        MemorySegment cipher;
        if (type != null) {
            requiredKeyLength = type.keyLength;
            requiredIvLength = type.ivLength;
            cipher = type.evpCipher;
        } else {
            if (!isInitialized()) {
                throw new IllegalArgumentException("Type must be specified");
            }
            requiredKeyLength = keyLength();
            requiredIvLength = ivLength();
            cipher = MemorySegment.NULL;
        }

        // Check if either the keylen or ivlen param exists and should be processed early.
        boolean updateRequiredKeyLength = false;
        boolean updateRequiredIvLength = false;
        if (paramBuffer.count() > 0) {
            if (paramBuffer.hasKey(EVP_CIPHER.CIPHER_PARAM_KEYLEN)) {
                updateRequiredKeyLength = key != null;
            }
            if (paramBuffer.hasKey(EVP_CIPHER.CIPHER_PARAM_IVLEN)) {
                updateRequiredIvLength = iv != null;
            }
        }

        // If any of the following initialization operations return an error code then the number
        // of bytes buffered by the (potentially partially initialized) cipher context is unknown
        // (until either the context is subsequently successfully initialized or EVP_CIPHER_CTX_reset
        // is called).
        this.bufferedBytes = UNKNOWN;

        if (updateRequiredKeyLength || updateRequiredIvLength) {
            // Update the required key and/or IV length before applying key or IV so that we can first
            // verify that the length of the supplied key and/or IV is the correct size.
            // Note that since not all cipher types accept a variable key or IV length we first call
            // EVP_CipherInit_ex2 to initialize the EVP_CIPHER_CTX with the EVP_CIPHER and params, look up
            // the new key length and/or IV length to verify the sizes of the supplied key and/or IV and
            // then make a second call to EVP_CipherInit_ex2 to apply the key and IV.
            // This also works around https://github.com/openssl/openssl/issues/19822 .
            // Note that if the supplied key or IV is not the correct size an IllegalArgumentException will
            // be thrown however the EVP_CIPHER_CTX will have been partially initialized.
            evpCipherInitEx2(cipher, MemorySegment.NULL, MemorySegment.NULL, enc, paramBuffer);
            cipher = MemorySegment.NULL;
            enc = NO_CHANGE;
            paramBuffer = EMPTY_PARAM_BUFFER;

            if (updateRequiredKeyLength) {
                requiredKeyLength = keyLength();
            }
            if (updateRequiredIvLength) {
                requiredIvLength = ivLength();
            }
        }

        MemorySegment keySeg = MemorySegment.NULL;
        MemorySegment ivSeg = MemorySegment.NULL;
        try {
            keySeg = allocateFromNullable(key, requiredKeyLength, "key", this.keyBufPA);
            // An AES/GCM nonce may be larger than MAX_IV_LENGTH as, if it is larger than 96 bits, it will first be digested with GMAC within OpenSSL.
            ivSeg = allocateFromNullable(iv, requiredIvLength, "iv", this.ivBufPA);
            evpCipherInitEx2(cipher, keySeg, ivSeg, enc, paramBuffer);
        } finally {
            keySeg.fill((byte) 0);
            ivSeg.fill((byte) 0);
        }

        if (type != null) {
            this.mode = type.mode;
            // Padding is enabled by default (for cipher modes that support padding) when a new 'algctx' is created.
            this.paddingEnabled = true;
        }
        if (this.mode == Mode.ECB || this.mode == Mode.CBC) {
            Optional<OSSL_PARAM> paddingParam = paramBuffer.locate(CIPHER_PARAM_PADDING);
            paddingParam.ifPresent(osslParam -> this.paddingEnabled = osslParam.intValue() != 0);
        }
    }

    void evpCipherInitEx2(MemorySegment cipher, MemorySegment keySeg, MemorySegment ivSeg, Enc enc, OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, this.paramBufSeg, (paramsSeg) -> {
            try {
                EVP_CIPHER_INIT_EX2_FUNC.invokeExact(this.evpCipherCtx, cipher, keySeg, ivSeg, enc.ordinal() - 1, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });

        // There are no buffered bytes after a successful call to EVP_CipherInit_ex2.
        this.bufferedBytes = 0L;
    }

    @Override
    public boolean isEncrypting() {
        try {
            return (boolean) EVP_CIPHER_CTX_IS_ENCRYPTING_FUNC.invokeExact(this.evpCipherCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    // NOTE: This method is able to handle MemorySegments larger than Integer.MAX_VALUE bytes in size,
    // despite the OpenSSL EVP_CipherUpdate method not being able to do so and despite the existing
    // callers (that take either byte arrays or ByteBuffers) not requiring this support, and therefore
    // returns a long rather than an int (indicating the amount of output).
    // This was done to be consistent with other methods in this OpenSSL adapter layer that are able to
    // support large amounts of input or output (primarily due to the underlying OpenSSL functions
    // already supporting that) and because support for handling large amounts of input and
    // output fell out of the "chunking" mechanism that had already been implemented to both handle a
    // corner case near the Integer.MAX_VALUE bytes boundary (when there is buffered data in the CTX)
    // and to limit the Time To Safe-Point (TTSP) when at least one of the buffers is on-heap
    // (non-native).
    long update(MemorySegment in, MemorySegment out) throws ShortBufferException {
        if (out.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }
        long bufferedLen = this.bufferedBytes;

        // If out is NULL then this call is updating Additional Authentication Data (AAD).
        // If out is not NULL, ensure that the out buffer has sufficient capacity.
        if (!out.isNative() || out.address() != 0L) {
            long outSize;
            long blkSz = this.blockSize();

            /*
             * Calculate outSize - the amount of output that will arise from processing the input.
             * It is used to determine if the out buffer has sufficient capacity.
             */
            if (this.mode == Mode.WRAP) {
                /*
                 * NOTE: blkSz is 8 for AES Key Wrap (RFC 3394 and RFC 5649).
                 * OpenSSL requires that all input is provided in the one EVP_CipherUpdate
                 * call with all output produced by the same call. Subsequent calls to
                 * EVP_CipherUpdate initiate a new wrap or unwrap operation.
                 */

                /*
                 * Check for an unsupported amount of input data.
                 * The input cannot be "chunked" so limit the input to TTSP_MAX_DATA bytes.
                 * Apply the same limit even if chunking is not required (i.e. even when
                 * both the "in" and "out" MemorySegments are native) for consistency.
                 */
                if (in.byteSize() > TTSP_MAX_DATA) {
                    throw new IllegalArgumentException("Unsupported amount of input data (Limit " + TTSP_MAX_DATA + " bytes): " + in.byteSize() + " bytes");
                }

                /*
                 * Initially set outSize to in.byteSize() rounded up to the next multiple of blkSz
                 * and then adjust it depending on whether encryption or decryption is being
                 * done.
                 * Note that for decryption, or for AES-WRAP (no padding) encryption,
                 * outSize will be equal to in.byteSize() as the input will already be a
                 * multiple of blkSz.
                 */
                outSize = (in.byteSize() + blkSz - 1L) & -blkSz;
                if (isEncrypting()) {
                    /*
                     * Encryption will produce an extra blkSz of output.
                     * outSize is exact amount of output that will be produced.
                     */
                    outSize += blkSz;
                } else {
                    /*
                     * Decryption will produce blkSz fewer bytes than was input.
                     * In this case outSize is the exact amount of output buffer space required.
                     * When decrypting with AES-WRAP-PAD note that OpenSSL will write
                     * additional zero bytes (the padding) up to the end of the outSize
                     * size buffer in the case where the plaintext size is not a multiple of
                     * blkSz but will report the size of the plaintext (which may be
                     * less than outSize as calculate here) as the number of bytes written.
                     */
                    outSize = outSize > blkSz ? outSize - blkSz : 0L;
                }
            } else if (this.mode == Mode.ECB || this.mode == Mode.CBC) {
                /* ECB or CBC mode. */
                if (bufferedLen == UNKNOWN) {
                    /*
                     * If the number of bytes currently internally buffered by the cipher context is UNKNOWN, because
                     * a previous operation returned an error code, then the exact output size cannot be determined.
                     */
                    throw new IllegalStateException("Unable to determine amount of buffered data after error");
                }

                /* Output length is the total input length rounded down to a multiple of the block size */
                long inTotal = Math.addExact(in.byteSize(), bufferedLen);
                outSize = inTotal & -blkSz;

                /* Special case for decrypting with PKCS5Padding */
                if (!isEncrypting() && this.paddingEnabled) {
                    /* If the amount of data to be processed is at least one block and is a
                     * multiple of the block size then one block will not be processed and
                     * will be retained in the EVP_CIPHER_CTX internal buffer until it can
                     * be determined whether that block is the final padding block.
                     */
                    if (outSize > 0 && outSize == inTotal) {
                        outSize -= blkSz;
                    }
                }
                bufferedLen = inTotal - outSize;
            } else {
                // Assume outSize == in.byteSize() for all other modes.
                outSize = in.byteSize();
            }
            if (outSize > out.byteSize()) {
                throw new ShortBufferException("Output buffer is of insufficient size");
            }
            out = out.asSlice(0L, outSize);
        }

        this.bufferedBytes = UNKNOWN;
        boolean nativeBuffers = in.isNative() && out.isNative();
        long chunkSize = nativeBuffers ? MAX_UPDATE_CHUNK_SIZE : TTSP_MAX_DATA;
        long n = 0L;
        while (in.byteSize() > 0L) {
            long inLen = Math.min(in.byteSize(), chunkSize);
            try {
                if (nativeBuffers) {
                    EVP_CIPHER_UPDATE_FUNC.invokeExact(this.evpCipherCtx, out, this.outLenSeg, in, (int) inLen);
                } else {
                    EVP_CIPHER_UPDATE_HEAP_FUNC.invokeExact(this.evpCipherCtx, out, this.outLenSeg, in, (int) inLen);
                }
            } catch (Throwable t) {
                throw mapException(t);
            }
            long outLen = this.outLenSeg.get(C_INT, 0L);
            if (!out.isNative() || out.address() != 0L) {
                if (outLen > out.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                out = out.asSlice(outLen);
                n += outLen;
            } else {
                if (outLen != inLen) {
                    throw new AssertionError("Internal error: Incorrect outl value for AAD update: " + outLen);
                }
            }
            in = in.asSlice(inLen);
        }

        this.bufferedBytes = bufferedLen;
        return n;
    }

    @Override
    public int update(ByteBuffer in, ByteBuffer out) throws ShortBufferException {
        MemorySegment outSeg = out != null ? MemorySegment.ofBuffer(out) : MemorySegment.NULL;
        int n = toIntExact(update(MemorySegment.ofBuffer(in), outSeg));
        in.position(in.limit());
        if (out != null) {
            out.position(out.position() + n);
        }
        return n;
    }

    @Override
    public int update(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException {
        if (inLen == 0) {
            return 0;
        }
        MemorySegment inSeg = MemorySegment.ofArray(in).asSlice(inOffset, inLen);
        MemorySegment outSeg = out != null ? MemorySegment.ofArray(out).asSlice(outOffset) : MemorySegment.NULL;
        return toIntExact(update(inSeg, outSeg));
    }

    int doFinal(MemorySegment out) throws ShortBufferException {
        if (out.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }

        /* EVP_CipherFinal_ex only produces output for ECB or CBC mode. */
        if (this.mode == Mode.ECB || this.mode == Mode.CBC) {
            /* Normally it only produces output (for these modes) if padding is enabled. */
            if (this.paddingEnabled) {
                /*
                 * For encryption maxOutLen is the exact amount of output that will be produced.
                 * For decryption maxOutLen is the required buffer space. The actual amount of
                 * output may be between zero and blockSize-1 bytes.
                 */
                long blkSz = this.blockSize();
                long maxOutLen = isEncrypting() ? blkSz : blkSz - 1;
                if (maxOutLen > out.byteSize()) {
                    throw new ShortBufferException("Output buffer is of insufficient size");
                }
                out = out.asSlice(0L, maxOutLen);
             } else {
                /*
                 * However, if padding was enabled during the last update call then the cipher engine
                 * will potentially have buffered what it thought at the time to be padding bytes.
                 * If padding was then disabled before doFinal was called then any buffered bytes
                 * will be processed and potentially output by EVP_CipherFinal_ex.
                 */
                if (this.bufferedBytes > out.byteSize()) {
                    throw new ShortBufferException("Output buffer is of insufficient size");
                }
            }
        }

        this.bufferedBytes = UNKNOWN;
        if (out.byteSize() > MAX_BLOCK_LENGTH) {
            out = out.asSlice(0L, MAX_BLOCK_LENGTH);
        }
        MemorySegment outSeg = toOffHeapSegment(out, this.blockBufPA);
        try {
            EVP_CIPHER_FINAL_EX_FUNC.invokeExact(this.evpCipherCtx, outSeg, this.outLenSeg);
        } catch (Throwable t) {
            throw mapException(t);
        }
        int n = this.outLenSeg.get(C_INT, 0L);
        if (n > out.byteSize()) {
            throw new AssertionError("Internal error: Buffer overrun");
        }

        if (!out.isNative() && n > 0) {
            MemorySegment.copy(outSeg, 0L, out, 0L, n);
            if (!isEncrypting()) {
                // Clear sensitive data.
                outSeg.asSlice(0L, n).fill((byte) 0);
            }
        }
        this.bufferedBytes = 0L;
        return n;
    }

    @Override
    public int doFinal(ByteBuffer out) throws ShortBufferException {
        int n = doFinal(MemorySegment.ofBuffer(out));
        out.position(out.position() + n);
        return n;
    }

    @Override
    public int doFinal(byte[] out, int outOffset) throws ShortBufferException {
        return doFinal(MemorySegment.ofArray(out).asSlice(outOffset));
    }
}
