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

import java.security.Security;

import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceMlPrivateKey.EncodingScheme;

import static java.lang.Math.max;

public class ToolkitProperties {

    private ToolkitProperties() {}

    private static final String OS_NAME_PROPERTY = "os.name";
    private static final String OS_ARCH_PROPERTY = "os.arch";
    private static final String JAVA_SECURITY_DEBUG_PROPERTY = "java.security.debug";
    private static final String JAVA_VENDOR_PROPERTY = "java.vendor";
    private static final String JAVA_RUNTIME_VERSION_PROPERTY = "java.runtime.version";

    private static final String JDK_DEFAULT_KEY_SIZE_PROPERTY = "jdk.security.defaultKeySize";
    private static final EncodingScheme DEFAULT_ML_PRIVATE_KEY_ENCODING = EncodingScheme.SEED;
    private static final String JDK_ML_KEM_PRIVATE_KEY_ENCODING = "jdk.mlkem.pkcs8.encoding";
    private static final String JDK_ML_DSA_PRIVATE_KEY_ENCODING = "jdk.mldsa.pkcs8.encoding";

    private static final int JIPHER_PBKDF2_DEFAULT_MINIMUM_PASSWORD_LENGTH = 8;
    private static final int JIPHER_PBKDF2_DEFAULT_MAXIMUM_ITERATION_COUNT = 10_000_000;

    private static final String JIPHER_OPENSSL_DIR_PROPERTY = "jipher.openssl.dir";
    private static final String JIPHER_OPENSSL_USE_OS_INSTANCE_PROPERTY = "jipher.openssl.useOsInstance";

    private static final String JIPHER_OPENSSL_SANCTIONED_CRYPTO_LIBRARY_VERSIONS_PROPERTY =
            "jipher.openssl.sanctioned.cryptoLibraryVersions";
    private static final String JIPHER_OPENSSL_SANCTIONED_FIPS_PROVIDER_VERSIONS_PROPERTY =
            "jipher.openssl.sanctioned.fipsProviderVersions";

    private static final String JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_CRYPTO_LIBRARY_VERSIONS_PROPERTY =
            "jipher.openssl.sanctioned.osProvided.cryptoLibraryVersions";
    private static final String JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_FIPS_PROVIDER_VERSIONS_PROPERTY =
            "jipher.openssl.sanctioned.osProvided.fipsProviderVersions";

    private static final String JIPHER_FIPS_ENFORCEMENT_PROPERTY = "jipher.fips.enforcement";
    private static final String JIPHER_CIPHER_AEAD_STREAM_PROPERTY = "jipher.cipher.AEAD.stream";
    private static final String JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH_PROPERTY = "jipher.pbkdf2.minimumPasswordLength";
    private static final String JIPHER_PBKDF2_MAXIMUM_ITERATION_COUNT_PROPERTY = "jipher.pbkdf2.maximumIterationCount";

    private static final String OS_NAME_VALUE = systemProperty(OS_NAME_PROPERTY);
    private static final String OS_ARCH_VALUE = systemProperty(OS_ARCH_PROPERTY);
    private static final String JAVA_SECURITY_DEBUG_VALUE = systemProperty(JAVA_SECURITY_DEBUG_PROPERTY);
    private static final String JAVA_VENDOR_VALUE = systemProperty(JAVA_VENDOR_PROPERTY);
    private static final String JAVA_RUNTIME_VERSION_VALUE = systemProperty(JAVA_RUNTIME_VERSION_PROPERTY);

    private static final String JIPHER_OPENSSL_DIR_VALUE = systemProperty(JIPHER_OPENSSL_DIR_PROPERTY);
    private static final boolean JIPHER_OPENSSL_USE_OS_INSTANCE_VALUE =  Boolean.getBoolean(JIPHER_OPENSSL_USE_OS_INSTANCE_PROPERTY);

    private static final String JIPHER_OPENSSL_SANCTIONED_CRYPTO_LIBRARY_VERSIONS_VALUE =
            systemProperty(JIPHER_OPENSSL_SANCTIONED_CRYPTO_LIBRARY_VERSIONS_PROPERTY,
                    "@SANCTIONED_CRYPTO_LIBRARY_VERSIONS_DEFAULT_VALUE@");
    private static final String JIPHER_OPENSSL_SANCTIONED_FIPS_PROVIDER_VERSIONS_VALUE =
            systemProperty(JIPHER_OPENSSL_SANCTIONED_FIPS_PROVIDER_VERSIONS_PROPERTY,
                    "@SANCTIONED_FIPS_PROVIDER_VERSIONS_DEFAULT_VALUE@");

    private static final String JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_CRYPTO_LIBRARY_VERSIONS_VALUE =
            systemProperty(JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_CRYPTO_LIBRARY_VERSIONS_PROPERTY,
                    "@SANCTIONED_OS_PROVIDED_CRYPTO_LIBRARY_VERSIONS_DEFAULT_VALUE@");
    private static final String JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_FIPS_PROVIDER_VERSIONS_VALUE =
            systemProperty(JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_FIPS_PROVIDER_VERSIONS_PROPERTY,
                    "@SANCTIONED_OS_PROVIDED_FIPS_PROVIDER_VERSIONS_DEFAULT_VALUE@");

    private static final Fips.EnforcementPolicy JIPHER_FIPS_ENFORCEMENT_VALUE = Fips.EnforcementPolicy.valueOf(
            systemProperty(JIPHER_FIPS_ENFORCEMENT_PROPERTY, Fips.EnforcementPolicy.FIPS.name()).toUpperCase());
    private static final boolean JIPHER_CIPHER_AEAD_STREAM_VALUE =
            Boolean.getBoolean(JIPHER_CIPHER_AEAD_STREAM_PROPERTY);
    private static final int JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH_VALUE =
            max(0, Integer.getInteger(JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH_PROPERTY, JIPHER_PBKDF2_DEFAULT_MINIMUM_PASSWORD_LENGTH));
    private static final int JIPHER_PBKDF2_MAXIMUM_ITERATION_COUNT_VALUE =
            max(0, Integer.getInteger(JIPHER_PBKDF2_MAXIMUM_ITERATION_COUNT_PROPERTY, JIPHER_PBKDF2_DEFAULT_MAXIMUM_ITERATION_COUNT));

    private static String systemProperty(final String property) {
        return System.getProperty(property);
    }

    private static String systemProperty(final String property, final String defaultVal) {
        return System.getProperty(property, defaultVal);
    }

    public static String getOsNameValue() {
        return OS_NAME_VALUE;
    }

    public static String getOsArchValue() {
        return OS_ARCH_VALUE;
    }

    public static String getJavaSecurityDebugValue() {
        return JAVA_SECURITY_DEBUG_VALUE;
    }

    public static String getJavaVendorValue() {
        return JAVA_VENDOR_VALUE;
    }

    public static String getJavaRuntimeVersionValue() {
        return JAVA_RUNTIME_VERSION_VALUE;
    }

    private static String getOverridableProperty(final String property) {
        String propVal = System.getProperty(property);
        if (propVal == null) {
            propVal = Security.getProperty(property);
        }
        return propVal;
    }

    private static EncodingScheme getEncodingScheme(String property) {
        String propVal = getOverridableProperty(property);
        return propVal == null ? DEFAULT_ML_PRIVATE_KEY_ENCODING : EncodingScheme.valueOf(propVal.toUpperCase());
    }

    public static EncodingScheme getMLKEMEncodingScheme() {
        return getEncodingScheme(JDK_ML_KEM_PRIVATE_KEY_ENCODING);
    }

    public static EncodingScheme getMLDSAEncodingScheme() {
        return getEncodingScheme(JDK_ML_DSA_PRIVATE_KEY_ENCODING);
    }

    public static String getJavaKeyLengths() {
        return systemProperty(JDK_DEFAULT_KEY_SIZE_PROPERTY);
    }

    public static String getOpenSslDirValue() {
        return JIPHER_OPENSSL_DIR_VALUE;
    }

    public static boolean getOpenSSLUseOsInstanceValue() {
        return JIPHER_OPENSSL_USE_OS_INSTANCE_VALUE;
    }

    public static String getOpensslSanctionedCryptoLibraryVersionsValue() {
        return JIPHER_OPENSSL_SANCTIONED_CRYPTO_LIBRARY_VERSIONS_VALUE;
    }
    public static String getOpensslSanctionedFipsProviderVersionsValue() {
        return JIPHER_OPENSSL_SANCTIONED_FIPS_PROVIDER_VERSIONS_VALUE;
    }
    public static String getOpensslSanctionedOsProvidedCryptoLibraryVersionsValue() {
        return JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_CRYPTO_LIBRARY_VERSIONS_VALUE;
    }
    public static String getOpensslSanctionedOsProvidedFipsProviderVersionsValue() {
        return JIPHER_OPENSSL_SANCTIONED_OS_PROVIDED_FIPS_PROVIDER_VERSIONS_VALUE;
    }

    public static Fips.EnforcementPolicy getFipsEnforcementValue() {
        return JIPHER_FIPS_ENFORCEMENT_VALUE;
    }

    public static boolean getJipherCipherAeadStreamValue() {
        return JIPHER_CIPHER_AEAD_STREAM_VALUE;
    }

    public static int getJipherPbkdf2MinimumPasswordLengthValue() {
        return JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH_VALUE;
    }

    public static int getJipherPbkdf2MaximumIterationCountValue() {
        return JIPHER_PBKDF2_MAXIMUM_ITERATION_COUNT_VALUE;
    }
}
