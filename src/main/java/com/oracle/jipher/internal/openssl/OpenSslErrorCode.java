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

public interface OpenSslErrorCode {

    /* OpenSSL error code flags and masks. See error code packing diagrams in include/openssl/err.h */
    int ERR_SYSTEM_FLAG       = 0x80000000;
    int ERR_SYSTEM_MASK       = Integer.MAX_VALUE;
    int ERR_LIB_OFFSET        = 23;
    int ERR_LIB_MASK          = 0xFF;
    int ERR_RFLAGS_OFFSET     = 18;
    int ERR_RFLAGS_MASK       = 0x1F;
    int ERR_REASON_MASK       = 0x7FFFFF;

    int ERR_RFLAG_FATAL       = 0x1 << ERR_RFLAGS_OFFSET;
    int ERR_RFLAG_COMMON      = 0x2 << ERR_RFLAGS_OFFSET;
    int ERR_R_FATAL           = ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;

    int ERR_R_MALLOC_FAILURE  = 256 | ERR_R_FATAL;

    int ERR_LIB_NONE          = 1;
    int ERR_LIB_SYS           = 2;
    int ERR_LIB_BN            = 3;
    int ERR_LIB_RSA           = 4;
    int ERR_LIB_DH            = 5;
    int ERR_LIB_EVP           = 6;
    int ERR_LIB_BUF           = 7;
    int ERR_LIB_OBJ           = 8;
    int ERR_LIB_PEM           = 9;
    int ERR_LIB_DSA           = 10;
    int ERR_LIB_ASN1          = 13;
    int ERR_LIB_CONF          = 14;
    int ERR_LIB_CRYPTO        = 15;
    int ERR_LIB_EC            = 16;
    int ERR_LIB_BIO           = 32;
    int ERR_LIB_X509V3        = 34;
    int ERR_LIB_PKCS12        = 35;
    int ERR_LIB_RAND          = 36;
    int ERR_LIB_DSO           = 37;
    int ERR_LIB_COMP          = 41;
    int ERR_LIB_ECDSA         = 42;
    int ERR_LIB_ECDH          = 43;
    int ERR_LIB_FIPS          = 45;
    int ERR_LIB_PROV          = 57;

    int EVP_R_NO_CIPHER_SET   = 131;
    int EVP_R_NO_DIGEST_SET   = 139;
    int EVP_R_MESSAGE_DIGEST_IS_NULL = 159;
    int EVP_R_PROVIDER_SIGNATURE_FAILURE = 234;

    /**
     * Returns <code>true</code> if the specified error is an OpenSSL system error.
     *
     * @return <code>true</code> if the error is a system error, <code>false</code> otherwise
     */
    static boolean isSystemError(int errorCode) {
        return (errorCode & ERR_SYSTEM_FLAG) != 0;
    }

    /**
     * Returns the LIB field of the specified error.
     *
     * @param errorCode the error code
     *  @return the LIB field of the error code
     */
    static int getLib(int errorCode) {
        if (isSystemError(errorCode)) {
            return ERR_LIB_SYS;
        }
        return (errorCode >> ERR_LIB_OFFSET) & ERR_LIB_MASK;
    }

    /**
     * Returns the RFLAGS field of the specified error.
     *
     * @param errorCode the error code
     *  @return the RFLAGS field of the error code
     */
    static int getRFlags(int errorCode) {
        if (isSystemError(errorCode)) {
            return 0;
        }
        return errorCode & (ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
    }

    /**
     * Returns the reason code of the specified error.
     *
     * @param errorCode the error code
     *  @return the reason code component of the error code
     */
    static int getReason(int errorCode) {
        if (isSystemError(errorCode)) {
            return errorCode & ERR_SYSTEM_MASK;
        }
        return errorCode & ERR_REASON_MASK;
    }

    /**
     * Returns <code>true</code> if the specified error is a fatal error.
     *
     * @param errorCode the error code
     * @return <code>true</code> if the error is a fatal error, <code>false</code> otherwise
     */
    static boolean isFatalError(int errorCode) {
        return (getRFlags(errorCode) & ERR_RFLAG_FATAL) != 0;
    }

    /**
     * Returns <code>true</code> if the specified error is a common error.
     *
     * @param errorCode the error code
     * @return <code>true</code> if the error is a common error, <code>false</code> otherwise
     */
    static boolean isCommonError(int errorCode) {
        return (getRFlags(errorCode) & ERR_RFLAG_COMMON) != 0;
    }
}
