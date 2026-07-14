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

package com.oracle.jiphertest.util;

import static org.junit.Assert.assertTrue;

public class FipsProviderInfoUtil {
    private static final String NAME;
    private static final String VERSION;
    private static final int MAJOR_VERSION;
    private static final int MINOR_VERSION;
    private static final int PATCH_VERSION;

    private static final boolean DESEDE_IS_SUPPORTED;
    private static final boolean DSA_IS_SUPPORTED;
    private static final boolean SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED;
    private static final boolean FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED;
    private static final int     KDF_MIN_PWD_LEN;
    private static final boolean ML_KEM_IS_SUPPORTED;
    private static final boolean ML_DSA_IS_SUPPORTED;

    static {
        // Determine the OpenSSL FIPS provider name and version:
        String jipherInfo = ProviderUtil.get().getInfo();
        String openSSLInfo = jipherInfo.substring(jipherInfo.indexOf('[') + 1, jipherInfo.indexOf(']'));
        String fipsProvider = openSSLInfo.split(" with ")[1];
        NAME = fipsProvider.split(" version ")[0];
        VERSION = fipsProvider.split(" version ")[1];

        // Drop build number from version string
        String patchVersion = VERSION.split("-")[0];
        String[] patchVersionParts = patchVersion.split("\\.");
        MAJOR_VERSION = Integer.parseInt(patchVersionParts[0]);
        MINOR_VERSION = patchVersionParts.length > 1 ? Integer.parseInt(patchVersionParts[1]) : 0;
        PATCH_VERSION = patchVersionParts.length > 2 ?Integer.parseInt(patchVersionParts[2]) : 0;
        boolean isPQCSupported;
        if (MAJOR_VERSION >=3 && MINOR_VERSION >=5) {
            isPQCSupported = true;
        } else {
            isPQCSupported = false;
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
            KDF_MIN_PWD_LEN = 8;
            isPQCSupported |= MAJOR_VERSION == 1;
        } else {
            DESEDE_IS_SUPPORTED = true;
            DSA_IS_SUPPORTED = true;
            SHA1_DIGEST_SIGNATURES_ARE_SUPPORTED = true;
            FIPS_186_4_TYPE_DOMAIN_PARAMETERS_SUPPORTED = true;
            KDF_MIN_PWD_LEN = 0;
        }
        ML_KEM_IS_SUPPORTED = ML_DSA_IS_SUPPORTED = isPQCSupported;
    }

    public static String getName() {
        return NAME;
    }

    public static String getVersionString() {
        return VERSION;
    }

    public static int getMajorVersion() {
        return MAJOR_VERSION;
    }

    public static int getMinorVersion() {
        return MINOR_VERSION;
    }

    public static int getPatchVersion() {
        return PATCH_VERSION;
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
        return KDF_MIN_PWD_LEN;
    }
    public static boolean isMlKemSupported() {
        return ML_KEM_IS_SUPPORTED;
    }
    public static boolean isMlDsaSupported() {
        return ML_DSA_IS_SUPPORTED;
    }
}
