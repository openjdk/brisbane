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
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.oracle.jipher.internal.openssl.EVP_CIPHER;
import com.oracle.jipher.internal.openssl.EVP_KDF;
import com.oracle.jipher.internal.openssl.EVP_MAC;
import com.oracle.jipher.internal.openssl.EVP_MD;
import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.EVP_PKEY_CTX;
import com.oracle.jipher.internal.openssl.EVP_RAND;
import com.oracle.jipher.internal.openssl.EVP_RAND_CTX;
import com.oracle.jipher.internal.openssl.OSSL_LIB_CTX;
import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OpenSslException;
import com.oracle.jipher.internal.openssl.OsslArena;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.ALL_PROVIDED_CALLBACK_UPCALL_STUB;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.CALLBACK_CONTEXT;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_LONG;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.CallbackContext;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DO_ALL_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DO_ALL_PROVIDED_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FETCH_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PROVIDER_CALLBACK_UPCALL_STUB;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PTR_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.callProviderCallback;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.constString;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

final class OsslLibCtx implements OSSL_LIB_CTX {

    static final MethodHandle OSSL_LIB_CTX_NEW_FUNC;
    static final MethodHandle OSSL_PROVIDER_SET_DEFAULT_SEARCH_PATH_FUNC;
    static final MethodHandle OSSL_LIB_CTX_LOAD_CONFIG_FUNC;
    static final MethodHandle OSSL_PROVIDER_AVAILABLE_FUNC;
    static final MethodHandle OSSL_PROVIDER_DO_ALL_FUNC;
    static final MethodHandle EVP_SET_DEFAULT_PROPERTIES_FUNC;
    static final MethodHandle EVP_DEFAULT_PROPERTIES_ENABLE_FIPS_FUNC;
    static final MethodHandle EVP_DEFAULT_PROPERTIES_IS_FIPS_ENABLED_FUNC;
    static final MethodHandle OSSL_LIB_CTX_FREE_FUNC;

    static final MethodHandle RAND_BYTES_EX_FUNC;
    static final MethodHandle RAND_PRIV_BYTES_EX_FUNC;
    static final MethodHandle RAND_GET0_PRIMARY_FUNC;

    static final MethodHandle NCONF_NEW_EX_FUNC;
    static final MethodHandle NCONF_LOAD_BIO_FUNC;
    static final MethodHandle CONF_MODULES_LOAD_FUNC;
    static final MethodHandle NCONF_FREE_FUNC;
    static final MethodHandle BIO_NEW_MEM_BUF_FUNC;
    static final MethodHandle BIO_V_FREE_FUNC;

    static final MethodHandle EVP_CIPHER_DO_ALL_PROVIDED_FUNC;
    static final MethodHandle EVP_CIPHER_FETCH_FUNC;
    static final MethodHandle EVP_KDF_DO_ALL_PROVIDED_FUNC;
    static final MethodHandle EVP_KDF_FETCH_FUNC;
    static final MethodHandle EVP_MAC_DO_ALL_PROVIDED_FUNC;
    static final MethodHandle EVP_MAC_FETCH_FUNC;
    static final MethodHandle EVP_MD_DO_ALL_PROVIDED_FUNC;
    static final MethodHandle EVP_MD_FETCH_FUNC;
    static final MethodHandle EVP_RAND_DO_ALL_PROVIDED_FUNC;
    static final MethodHandle EVP_RAND_FETCH_FUNC;

    static final MethodHandle EVP_PKEY_CTX_NEW_FROM_NAME_FUNC;
    static final MethodHandle EVP_PKEY_CTX_NEW_FROM_PKEY_FUNC;

    static {
        OSSL_LIB_CTX_NEW_FUNC = downcallHandleCheckNull(
                "OSSL_LIB_CTX_new", NEW_FUNCDESC);
        OSSL_PROVIDER_SET_DEFAULT_SEARCH_PATH_FUNC = downcallHandleCheckZeroNeg(
                "OSSL_PROVIDER_set_default_search_path", "(MM)I");
        OSSL_LIB_CTX_LOAD_CONFIG_FUNC = downcallHandleCheckZeroNeg(
                "OSSL_LIB_CTX_load_config", "(MM)I");
        OSSL_PROVIDER_AVAILABLE_FUNC = downcallHandle(
                "OSSL_PROVIDER_available", "(MM)Z");
        OSSL_PROVIDER_DO_ALL_FUNC = downcallHandle(
                "OSSL_PROVIDER_do_all", DO_ALL_FUNCDESC);
        EVP_SET_DEFAULT_PROPERTIES_FUNC = downcallHandleCheckZeroNeg(
                "EVP_set_default_properties", "(MM)I");
        EVP_DEFAULT_PROPERTIES_ENABLE_FIPS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_default_properties_enable_fips", "(MI)I");
        EVP_DEFAULT_PROPERTIES_IS_FIPS_ENABLED_FUNC = downcallHandle(
                "EVP_default_properties_is_fips_enabled", "(M)Z");
        OSSL_LIB_CTX_FREE_FUNC = downcallHandle(
                "OSSL_LIB_CTX_free", FREE_FUNCDESC);

        RAND_BYTES_EX_FUNC = downcallHandleCheckZeroNeg(
                "RAND_bytes_ex", "(MMSI)I");
        RAND_PRIV_BYTES_EX_FUNC = downcallHandleCheckZeroNeg(
                "RAND_priv_bytes_ex", "(MMSI)I");
        RAND_GET0_PRIMARY_FUNC = downcallHandle(
                "RAND_get0_primary", PTR_FUNCDESC, CRITICAL);

        NCONF_NEW_EX_FUNC = downcallHandleCheckNull(
                "NCONF_new_ex", "(MM)M");
        NCONF_LOAD_BIO_FUNC = downcallHandleCheckZeroNeg(
                "NCONF_load_bio", "(MMM)I");
        CONF_MODULES_LOAD_FUNC = downcallHandleCheckZeroNeg(
                "CONF_modules_load", "(MML)I");
        NCONF_FREE_FUNC = downcallHandle(
                "NCONF_free", FREE_FUNCDESC);
        BIO_NEW_MEM_BUF_FUNC = downcallHandleCheckNull(
                "BIO_new_mem_buf", "(MI)M");
        BIO_V_FREE_FUNC = downcallHandle(
                "BIO_vfree", FREE_FUNCDESC);

        EVP_CIPHER_DO_ALL_PROVIDED_FUNC = downcallHandle(
                "EVP_CIPHER_do_all_provided", DO_ALL_PROVIDED_FUNCDESC);
        EVP_CIPHER_FETCH_FUNC = downcallHandleCheckNull(
                "EVP_CIPHER_fetch", FETCH_FUNCDESC);
        EVP_KDF_DO_ALL_PROVIDED_FUNC = downcallHandle(
                "EVP_KDF_do_all_provided", DO_ALL_PROVIDED_FUNCDESC);
        EVP_KDF_FETCH_FUNC = downcallHandleCheckNull(
                "EVP_KDF_fetch", FETCH_FUNCDESC);
        EVP_MAC_DO_ALL_PROVIDED_FUNC = downcallHandle(
                "EVP_MAC_do_all_provided", DO_ALL_PROVIDED_FUNCDESC);
        EVP_MAC_FETCH_FUNC = downcallHandleCheckNull(
                "EVP_MAC_fetch", FETCH_FUNCDESC);
        EVP_MD_DO_ALL_PROVIDED_FUNC = downcallHandle(
                "EVP_MD_do_all_provided", DO_ALL_PROVIDED_FUNCDESC);
        EVP_MD_FETCH_FUNC = downcallHandleCheckNull(
                "EVP_MD_fetch", FETCH_FUNCDESC);
        EVP_RAND_DO_ALL_PROVIDED_FUNC = downcallHandle(
                "EVP_RAND_do_all_provided", DO_ALL_PROVIDED_FUNCDESC);
        EVP_RAND_FETCH_FUNC = downcallHandleCheckNull(
                "EVP_RAND_fetch", FETCH_FUNCDESC);

        EVP_PKEY_CTX_NEW_FROM_NAME_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_CTX_new_from_name", FETCH_FUNCDESC);
        EVP_PKEY_CTX_NEW_FROM_PKEY_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_CTX_new_from_pkey", FETCH_FUNCDESC);
    }

    final MemorySegment osslLibCtx;

    OsslLibCtx() {
        this.osslLibCtx = MemorySegment.NULL;
    }

    public OsslLibCtx(Arena arena) {
        MemorySegment osslLibCtx;
        try {
            osslLibCtx = (MemorySegment) OSSL_LIB_CTX_NEW_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.osslLibCtx = osslLibCtx.reinterpret(arena, OsslLibCtx::free);
    }

    static void free(MemorySegment seg) {
        try {
            OSSL_LIB_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void setDefaultProviderSearchPath(String modulesPath) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment modulesPathStr = arena.allocateFrom(modulesPath);
            try {
                OSSL_PROVIDER_SET_DEFAULT_SEARCH_PATH_FUNC.invokeExact(this.osslLibCtx, modulesPathStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public void loadConfig(String configFile) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment configFileStr = arena.allocateFrom(configFile);
            try {
                OSSL_LIB_CTX_LOAD_CONFIG_FUNC.invokeExact(this.osslLibCtx, configFileStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public boolean isProviderAvailable(String providerName) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment providerNameStr = arena.allocateFrom(providerName);
            try {
                return (boolean) OSSL_PROVIDER_AVAILABLE_FUNC.invokeExact(this.osslLibCtx, providerNameStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public <T> Optional<T> forProvider(String providerName, Function<OSSL_PROVIDER,? extends T> mapper) {
        Stream.Builder<T> sb = Stream.builder();
        forEachProvider(provider -> {
            if (provider.name().equals(providerName)) {
                sb.add(mapper.apply(provider));
                // OSSL_PROVIDER_do_all() callback processing stops at the first callback invocation that returns 0.
                return false;
            }
            return true;
        });
        return sb.build().findAny();
    }

    @Override
    public boolean forEachProvider(Predicate<OSSL_PROVIDER> callback) {
       return callProviderCallback(() -> {
            try {
                return (boolean) OSSL_PROVIDER_DO_ALL_FUNC.invokeExact(this.osslLibCtx, PROVIDER_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }, callback);
    }

    @Override
    public void setDefaultProperties(String propq) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment propqStr = arena.allocateFrom(propq);
            try {
                EVP_SET_DEFAULT_PROPERTIES_FUNC.invokeExact(this.osslLibCtx, propqStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public void enableFips(boolean enable) {
        try {
            EVP_DEFAULT_PROPERTIES_ENABLE_FIPS_FUNC.invokeExact(this.osslLibCtx, enable ? 1 : 0);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public boolean isFipsEnabled() {
        try {
            return (boolean) EVP_DEFAULT_PROPERTIES_IS_FIPS_ENABLED_FUNC.invokeExact(this.osslLibCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void randBytes(byte[] bytes, int strength) {
        try (Arena arena = Arena.ofConfined()) {
            long bytesLen = bytes.length;
            MemorySegment bytesSeg = OpenSslAllocators.mallocClearFree(bytesLen, arena);
            try {
                RAND_BYTES_EX_FUNC.invokeExact(this.osslLibCtx, bytesSeg, bytesLen, strength);
            } catch (Throwable t) {
                throw mapException(t);
            }
            MemorySegment.copy(bytesSeg, JAVA_BYTE, 0L, bytes, 0, bytes.length);
        }
    }

    @Override
    public void randPrivBytes(byte[] bytes, int strength) {
        try (Arena arena = Arena.ofConfined()) {
            long bytesLen = bytes.length;
            MemorySegment bytesSeg = OpenSslAllocators.mallocClearFree(bytesLen, arena);
            try {
                RAND_PRIV_BYTES_EX_FUNC.invokeExact(this.osslLibCtx, bytesSeg, bytesLen, strength);
            } catch (Throwable t) {
                throw mapException(t);
            }
            MemorySegment.copy(bytesSeg, JAVA_BYTE, 0L, bytes, 0, bytes.length);
        }
    }

    @Override
    public EVP_RAND_CTX newEvpRandCtxWithPrimaryAsParent(EVP_RAND type, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment primaryRand;
        try {
            primaryRand = (MemorySegment) RAND_GET0_PRIMARY_FUNC.invokeExact(this.osslLibCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpRandCtx((EvpRand) type, primaryRand, arena);
    }

    @Override
    public void setConfig(String config) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment configStr = arena.allocateFrom(config);
            MemorySegment errorLineSeg = arena.allocate(C_LONG);
            if (C_LONG.byteSize() == Long.BYTES) {
                errorLineSeg.set(JAVA_LONG, 0L, -1L);
            } else {
                errorLineSeg.set(JAVA_INT, 0L, -1);
            }
            try {
                MemorySegment memBio = (MemorySegment) BIO_NEW_MEM_BUF_FUNC.invokeExact(configStr, -1);
                memBio = memBio.reinterpret(arena, OsslLibCtx::freeBio);
                MemorySegment conf = (MemorySegment) NCONF_NEW_EX_FUNC.invokeExact(this.osslLibCtx, MemorySegment.NULL);
                conf = conf.reinterpret(arena, OsslLibCtx::freeConf);
                try {
                    NCONF_LOAD_BIO_FUNC.invokeExact(conf, memBio, errorLineSeg);
                } catch (OpenSslException e) {
                    int errorLine;
                    if (C_LONG.byteSize() == Long.BYTES) {
                        errorLine = (int) errorLineSeg.get(JAVA_LONG, 0L);
                    } else {
                        errorLine = errorLineSeg.get(JAVA_INT, 0L);
                    }
                    if (errorLine >= 0) {
                        throw new OpenSslException("Error on line %d of config".formatted(errorLine), e, e.errorCode());
                    }
                    throw e;
                }
                if (C_LONG.byteSize() == Long.BYTES) {
                    CONF_MODULES_LOAD_FUNC.invokeExact(conf, MemorySegment.NULL, 0L);
                } else {
                    CONF_MODULES_LOAD_FUNC.invokeExact(conf, MemorySegment.NULL, 0);
                }
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    static void freeConf(MemorySegment conf) {
        try {
            NCONF_FREE_FUNC.invokeExact(conf);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static void freeBio(MemorySegment bio) {
        try {
            BIO_V_FREE_FUNC.invokeExact(bio);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void forEachCipher(Consumer<EVP_CIPHER> consumer) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(cipher -> {
                consumer.accept(new EvpCipher(cipher, arena, null));
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    EVP_CIPHER_DO_ALL_PROVIDED_FUNC.invokeExact(this.osslLibCtx, ALL_PROVIDED_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public EVP_CIPHER fetchCipher(String algorithm, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpCipher;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment algorithmStr = confinedArena.allocateFrom(algorithm);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpCipher = (MemorySegment) EVP_CIPHER_FETCH_FUNC.invokeExact(this.osslLibCtx, algorithmStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
            return new EvpCipher(evpCipher, arena);
        }
    }

    @Override
    public void forEachKdf(Consumer<EVP_KDF> consumer) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(kdf -> {
                consumer.accept(new EvpKdf(kdf, arena, null));
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    EVP_KDF_DO_ALL_PROVIDED_FUNC.invokeExact(this.osslLibCtx, ALL_PROVIDED_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public EVP_KDF fetchKdf(String algorithm, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpKdf;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment algorithmStr = confinedArena.allocateFrom(algorithm);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpKdf = (MemorySegment) EVP_KDF_FETCH_FUNC.invokeExact(this.osslLibCtx, algorithmStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpKdf(evpKdf, arena);
    }

    @Override
    public void forEachMac(Consumer<EVP_MAC> consumer) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(mac -> {
                consumer.accept(new EvpMac(mac, arena, null));
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    EVP_MAC_DO_ALL_PROVIDED_FUNC.invokeExact(this.osslLibCtx, ALL_PROVIDED_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public EVP_MAC fetchMac(String algorithm, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpMac;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment algorithmStr = confinedArena.allocateFrom(algorithm);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpMac = (MemorySegment) EVP_MAC_FETCH_FUNC.invokeExact(this.osslLibCtx, algorithmStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpMac(evpMac, arena);
    }

    @Override
    public void forEachMd(Consumer<EVP_MD> consumer) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(md -> {
                consumer.accept(new EvpMd(md, arena, null));
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    EVP_MD_DO_ALL_PROVIDED_FUNC.invokeExact(this.osslLibCtx, ALL_PROVIDED_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public EVP_MD fetchMd(String algorithm, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpMd;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment algorithmStr = confinedArena.allocateFrom(algorithm);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpMd = (MemorySegment) EVP_MD_FETCH_FUNC.invokeExact(this.osslLibCtx, algorithmStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpMd(evpMd, arena);
    }

    @Override
    public void forEachRand(Consumer<EVP_RAND> consumer) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(rand -> {
                consumer.accept(new EvpRand(rand, arena, null));
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    EVP_RAND_DO_ALL_PROVIDED_FUNC.invokeExact(this.osslLibCtx, ALL_PROVIDED_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public EVP_RAND fetchRand(String algorithm, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpRand;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment algorithmStr = confinedArena.allocateFrom(algorithm);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpRand = (MemorySegment) EVP_RAND_FETCH_FUNC.invokeExact(this.osslLibCtx, algorithmStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpRand(evpRand, arena);
    }

    @Override
    public EVP_PKEY_CTX newPkeyCtx(String name, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpPkeyCtx;
        try (Arena confinedArena = Arena.ofConfined()) {
            // The name string must remain valid until the EVP_PKEY_CTX and all duplicates have been freed.
            MemorySegment nameStr = constString(name);
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpPkeyCtx = (MemorySegment) EVP_PKEY_CTX_NEW_FROM_NAME_FUNC.invokeExact(this.osslLibCtx, nameStr, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpPkeyCtx(evpPkeyCtx, arena);
    }

    @Override
    public EVP_PKEY_CTX newPkeyCtx(EVP_PKEY pkey, String properties, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpPkeyCtx;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment propertiesStr = properties != null ? confinedArena.allocateFrom(properties) : MemorySegment.NULL;
            try {
                evpPkeyCtx = (MemorySegment) EVP_PKEY_CTX_NEW_FROM_PKEY_FUNC.invokeExact(this.osslLibCtx, ((EvpPkey) pkey).upRefInternal(confinedArena).evpPkey, propertiesStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
        return new EvpPkeyCtx(evpPkeyCtx, arena);
    }
}
