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

import static org.junit.Assert.assertTrue;

public class FipsProviderInfoUtil {
    private static final String NAME;
    private static final String VERSION;

    static private final boolean DESEDE_IS_SUPPORTED;
    static private final boolean DSA_IS_SUPPORTED;
    static private final boolean SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED;
    static private final boolean FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED;
    static private final int     KDF_MIN_PWD_LENGTH;
    private static final boolean ML_KEM_IS_SUPPORTED;
    private static final boolean ML_DSA_IS_SUPPORTED;


    static {
        NAME = FipsProviderInfo.getNameString();
        VERSION = FipsProviderInfo.getVersionString();
        // Drop build number from version string
        String patchVersion = VERSION.split("-")[0];
        String[] versionComponents = patchVersion.split("\\.");
        int majorVersion = -1;
        int minorVersion = -1;
        boolean isPQCSupported = false;
        if (versionComponents.length >= 2) {
            try {
                majorVersion = Integer.parseInt(versionComponents[0]);
                minorVersion = Integer.parseInt(versionComponents[1]);
                // FIPS certified support for PQC requires minor version >=5.
                isPQCSupported = (majorVersion == 3 && minorVersion >= 5);
            } catch (NumberFormatException e) {
                isPQCSupported = false;
            }
        }
        // Note: The OpenSSL FIPS provider used on version 9 of these Linux distributions is also used on version 10.
        boolean isRHDerivative = NAME.contains("Red Hat Enterprise Linux") || NAME.contains("Oracle Linux");

        if (isRHDerivative) {
            // These capabilities apply to versions 3.0.7 and 1.2.0 of the FIPS provider distributed with these Linux distributions.
            // This class will need to be updated to support any future version.
            assertTrue("3.0.7".equals(patchVersion) || "1.2.0".equals(patchVersion));

            DESEDE_IS_SUPPORTED = false;
            DSA_IS_SUPPORTED = false;
            SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED = false;
            FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED = false;
            KDF_MIN_PWD_LENGTH = 8;
            isPQCSupported |= majorVersion == 1;
        } else {
            DESEDE_IS_SUPPORTED = true;
            DSA_IS_SUPPORTED = true;
            SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED = true;
            FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED = true;
            KDF_MIN_PWD_LENGTH = 0;
        }
        ML_KEM_IS_SUPPORTED = isPQCSupported;
        ML_DSA_IS_SUPPORTED = isPQCSupported;
    }

    public static String getName() {
        return NAME;
    }

    public static String getVersionString() {
        return VERSION;
    }

    public static boolean isDESEDESupported() {
        return DESEDE_IS_SUPPORTED;
    }
    public static boolean isDSASupported() {
        return DSA_IS_SUPPORTED;
    }
    public static boolean isSHA1DigestSignatureSupported() {
        return SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED;
    }

    public static boolean isFIPS186_4TypeDomainParametersSupported() {
        return FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED;
    }

    public static int getKDFMinPwdLen() {
        return KDF_MIN_PWD_LENGTH;
    }
    public static boolean isMLKEMSupported() {
        return ML_KEM_IS_SUPPORTED;
    }
    public static boolean isMLDSASupported() {
        return ML_DSA_IS_SUPPORTED;
    }
}
