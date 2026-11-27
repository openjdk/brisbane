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
import java.lang.invoke.MethodHandle;
import java.util.function.Consumer;

import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DO_ALL_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DUP_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.GET0_STRING_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.IS_A_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NAME_CALLBACK_UPCALL_STUB;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PTR_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.UP_REF_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.callNameCallback;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.newOpenSslException;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_SEQUENCE_PTR;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newDataParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;

final class EvpPkey implements EVP_PKEY {

    static final MethodHandle EVP_PKEY_NEW_FUNC;
    static final MethodHandle EVP_PKEY_UP_REF_FUNC;
    static final MethodHandle EVP_PKEY_DUP_FUNC;
    static final MethodHandle EVP_PKEY_IS_A_FUNC;
    static final MethodHandle EVP_PKEY_TYPE_NAMES_DO_ALL_FUNC;
    static final MethodHandle EVP_PKEY_GET0_TYPE_NAME_FUNC;
    static final MethodHandle EVP_PKEY_GET0_DESCRIPTION_FUNC;
    static final MethodHandle EVP_PKEY_GET0_PROVIDER_FUNC;
    static final MethodHandle EVP_PKEY_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_GET_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_SET_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_TODATA_FUNC;
    static final MethodHandle EVP_PKEY_FREE_FUNC;

    static {
        EVP_PKEY_NEW_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_new", NEW_FUNCDESC);
        EVP_PKEY_UP_REF_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_up_ref", UP_REF_FUNCDESC);
        EVP_PKEY_DUP_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_dup", DUP_FUNCDESC);
        EVP_PKEY_IS_A_FUNC = downcallHandle(
                "EVP_PKEY_is_a", IS_A_FUNCDESC);
        EVP_PKEY_TYPE_NAMES_DO_ALL_FUNC = downcallHandle(
                "EVP_PKEY_type_names_do_all", DO_ALL_FUNCDESC);
        EVP_PKEY_GET0_TYPE_NAME_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_get0_type_name", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_PKEY_GET0_DESCRIPTION_FUNC = downcallHandle(
                "EVP_PKEY_get0_description", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_PKEY_GET0_PROVIDER_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_get0_provider", PTR_FUNCDESC, CRITICAL);
        EVP_PKEY_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_PKEY_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_PKEY_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_PKEY_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_PKEY_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_get_params", PARAMS_FUNCDESC);
        EVP_PKEY_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_set_params", PARAMS_FUNCDESC);
        EVP_PKEY_TODATA_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_todata", "(MIM)I");
        EVP_PKEY_FREE_FUNC = downcallHandle(
                "EVP_PKEY_free", FREE_FUNCDESC);
    }

    final MemorySegment evpPkey;
    final Consumer<MemorySegment> idempotentCleanup;
    boolean active;

    EvpPkey(Arena arena) {
        this(newPkey(), arena);
    }

    EvpPkey(MemorySegment evpPkey, Arena arena) {
        this.idempotentCleanup = new IdempotentCleanup();
        this.evpPkey = evpPkey.reinterpret(arena, this.idempotentCleanup);
        this.active = true;
    }

    static void freeInternal(MemorySegment seg) {
        try {
            EVP_PKEY_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static MemorySegment newPkey() {
        try {
            return (MemorySegment) EVP_PKEY_NEW_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    void checkActive() {
        if (!this.active) {
            throw new IllegalStateException("No longer active");
        }
    }

    // Forcibly free the OpenSSL EVP_PKEY early and ensure that the MemorySegment cleanup
    // will not result in a double free and that other methods on this class will not continue
    // to use this.evpPkey.
    // Other classes in this package should call upRefInternal(confinedArena) within a
    // try-with-resources that creates a confined Arena in order to safely access this.evpPkey.
    @Override
    public synchronized void free() {
        this.active = false;
        this.idempotentCleanup.accept(this.evpPkey);
    }

    @Override
    public EVP_PKEY upRef(OsslArena osslArena) {
        return upRefInternal(((ArenaImpl) osslArena).arena);
    }

    synchronized EvpPkey upRefInternal(Arena arena) {
        checkActive();
        MemorySegment evpPkeyPtr = MemorySegment.ofAddress(this.evpPkey.address());
        try {
            EVP_PKEY_UP_REF_FUNC.invokeExact(this.evpPkey);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpPkey(evpPkeyPtr, arena);
    }

    @Override
    public synchronized EVP_PKEY dup(OsslArena osslArena) {
        checkActive();
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment dup;
        try {
            dup = (MemorySegment) EVP_PKEY_DUP_FUNC.invokeExact(this.evpPkey);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpPkey(dup, arena);
    }

    @Override
    public synchronized boolean isA(String name) {
        checkActive();
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment nameStr = confinedArena.allocateFrom(name);
            try {
                return (boolean) EVP_PKEY_IS_A_FUNC.invokeExact(this.evpPkey, nameStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public synchronized boolean forEachTypeName(Consumer<String> consumer) {
        checkActive();
        return callNameCallback(() -> {
            try {
                return (boolean) EVP_PKEY_TYPE_NAMES_DO_ALL_FUNC.invokeExact(this.evpPkey, NAME_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }, consumer);
    }

    @Override
    public synchronized String typeName() {
        checkActive();
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_PKEY_GET0_TYPE_NAME_FUNC.invokeExact(this.evpPkey);
            return nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public synchronized String description() {
        checkActive();
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_PKEY_GET0_DESCRIPTION_FUNC.invokeExact(this.evpPkey);
            return nameSegment.address() == 0L ? null : nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public synchronized String providerName() {
        checkActive();
        OSSL_PROVIDER provider;
        try {
            provider = new OsslProvider((MemorySegment) EVP_PKEY_GET0_PROVIDER_FUNC.invokeExact(this.evpPkey));
        } catch (Throwable t) {
            throw mapException(t);
        }
        return provider.name();
    }

    @Override
    public synchronized OsslParamBuffer gettableParams() {
        checkActive();
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_PKEY_GETTABLE_PARAMS_FUNC.invokeExact(this.evpPkey));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public synchronized OsslParamBuffer settableParams() {
        checkActive();
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_PKEY_SETTABLE_PARAMS_FUNC.invokeExact(this.evpPkey));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public synchronized void getParams(OsslParamBuffer paramBuffer) {
        checkActive();
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_GET_PARAMS_FUNC.invokeExact(this.evpPkey, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public synchronized void setParams(OsslParamBuffer paramBuffer) {
        checkActive();
        withDataParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_SET_PARAMS_FUNC.invokeExact(this.evpPkey, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public synchronized OsslParamBuffer todata(Selection selection, OsslArena osslArena) {
        checkActive();
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment paramsSeg;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment paramsPtrSeg = confinedArena.allocate(C_OSSL_PARAM_SEQUENCE_PTR);
            try {
                EVP_PKEY_TODATA_FUNC.invokeExact(this.evpPkey, selection.mask, paramsPtrSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
            paramsSeg = paramsPtrSeg.get(C_OSSL_PARAM_SEQUENCE_PTR, 0L);
        }
        if (paramsSeg.address() == 0L) {
            throw newOpenSslException("EVP_PKEY_todata: out param buffer is NULL,");
        }
        return newDataParamBuffer(paramsSeg, arena, selection == Selection.PKEY_KEYPAIR);
    }

    private static class IdempotentCleanup implements Consumer<MemorySegment> {
        boolean cleaned = false;

        @Override
        public synchronized void accept(MemorySegment memorySegment) {
            if (!this.cleaned) {
                this.cleaned = true;
                freeInternal(memorySegment);
            }
        }
    }
}
