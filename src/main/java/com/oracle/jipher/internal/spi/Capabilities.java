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

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.openssl.FipsProviderInfo;

/**
 * Utility class exposing the cryptographic capabilities of the underlying OpenSSL
 * FIPS provider.  The values are determined at class-initialisation time based on
 * the name and version of the OpenSSL FIPS provider loaded by Jipher at runtime.
 *
 * <p> The OpenSSL FIPS provider shipped with Linux distributions such as Oracle Linux
 * does not support certain legacy algorithms; these are reported as not
 * supported.
 */
public class Capabilities {

    private static final boolean DESEDE_IS_SUPPORTED;
    private static final boolean DSA_IS_SUPPORTED;
    private static final boolean SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED;
    private static final boolean ML_KEM_IS_SUPPORTED;
    private static final boolean ML_DSA_IS_SUPPORTED;
    private static final Debug DEBUG = Debug.getInstance("jipher");

    // Initialise capability flags based on the OpenSSL FIPS provider name and version.
    static {
        String name = FipsProviderInfo.getNameString();
        String patchVersion = FipsProviderInfo.getVersionString();

        DEBUG.println("FIPS Provider detected " + name);
        DEBUG.println("FIPS Provider version " + patchVersion);

        int majorVersion = -1;
        int minorVersion = -1;
        boolean isPQCSupported = false;
        if (patchVersion != null) {
            String[] versionComponents = patchVersion.split("-")[0].split("\\.");
            if (versionComponents.length >= 2) {
                try {
                    majorVersion = Integer.parseInt(versionComponents[0]);
                    minorVersion = Integer.parseInt(versionComponents[1]);
                    DEBUG.println("FIPS Provider major version " + majorVersion);
                    DEBUG.println("FIPS Provider minor version " + minorVersion);
                    // FIPS certified support for PQC requires minor version >=5.
                    isPQCSupported = (majorVersion == 3 && minorVersion >= 5);
                } catch (NumberFormatException e) {
                    // Ignore
                }
            }
        }
        boolean isRHDerivative = (name != null) &&
                (name.contains("Red Hat Enterprise Linux") || name.contains("Oracle Linux"));

        if (isRHDerivative) {
            // For these Linux distributions, at the time of writing, only a single version, 3.0.7,
            // of the OpenSSL FIPS module is distributed.  This FIPS module:
            //  * was validated against FIPS-140-3.
            //  * is used on version 9 and on version 10 of these Linux distributions.
            // When these Linux distributions receive a CMVP certificate for a new FIPS module
            // the version number and possibly the name of that module will be different.
            // This class will need to be updated to infer the exact capabilities of that new FIPS module.
            // For the time being the safest fallback position this code can take if it encounters an
            // unexpected version of the FIPS module distributed with these Linux distributions
            // is to assume that it does not add support for the capabilities not present in 3.0.7
            DESEDE_IS_SUPPORTED = false;
            DSA_IS_SUPPORTED = false;
            SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED = false;
            // In case of OS supplied OpenSSL, versions 1.x based of Kryoptic support PQC.
            isPQCSupported |= majorVersion == 1;
        } else {
            DESEDE_IS_SUPPORTED = true;
            DSA_IS_SUPPORTED = true;
            SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED = true;
        }
        ML_KEM_IS_SUPPORTED = isPQCSupported;
        ML_DSA_IS_SUPPORTED = isPQCSupported;
    }

    // The following getters facilitate mocking.
    public static boolean isDESEDESupported() {
        return DESEDE_IS_SUPPORTED;
    }
    public static boolean isDSASupported() {
        return DSA_IS_SUPPORTED;
    }
    public static boolean isSHA1DigestSignatureSupported() {
        return SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED;
    }
    public static boolean isMlKemSupported() {
        return ML_KEM_IS_SUPPORTED;
    }
    public static boolean isMlDsaSupported() {
        return ML_DSA_IS_SUPPORTED;
    }
}
