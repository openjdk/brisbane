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

package com.oracle.jipher.provider;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.Provider;
import java.security.ProviderException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.FipsProviderInfo;
import com.oracle.jipher.internal.openssl.OpenSsl;
import com.oracle.jipher.internal.openssl.OpenSslValidator;
import com.oracle.jipher.internal.openssl.OpenSslVersion;
import com.oracle.jipher.internal.spi.Capabilities;
import com.oracle.jiphertest.util.EnvUtil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class JipherJCETest {

    private static final String TEST_CRYPTO_VERSION = "TEST CRYPTO VERSION STRING";
    private static final String TEST_FIPS_PROVIDER_NAME = "TEST FIPS NAME STRING";
    private static final String TEST_FIPS_PROVIDER_VERSION = "TEST FIPS VERSION STRING";
    private static final Map<String, String[]> SERVICE_ALGORITHMS;

    static {
        Map<String, String[]> serviceAlgorithms = new HashMap<>();

        serviceAlgorithms.put("AlgorithmParameters", new String[]{
                "AES",
                "DESede",
                "DH",
                "EC",
                "GCM",
                "OAEP",
                "PBE",
                "PBES2",
                "PBEWithHmacSHA1AndAES_128",
                "PBEWithHmacSHA1AndAES_256",
                "PBEWithHmacSHA224AndAES_128",
                "PBEWithHmacSHA224AndAES_256",
                "PBEWithHmacSHA256AndAES_128",
                "PBEWithHmacSHA256AndAES_256",
                "PBEWithHmacSHA384AndAES_128",
                "PBEWithHmacSHA384AndAES_256",
                "PBEWithHmacSHA512AndAES_128",
                "PBEWithHmacSHA512AndAES_256",
                "RSASSA-PSS"
        });
        serviceAlgorithms.put("Cipher", new String[]{
                "AES_128/CBC/PKCS5Padding",
                "AES_128/CFB/NoPadding",
                "AES_128/ECB/NoPadding",
                "AES_128/GCM/NoPadding",
                "AES_128/KW/NoPadding",
                "AES_128/KWP/NoPadding",
                "AES_128/OFB/NoPadding",
                "AES_192/CBC/PKCS5Padding",
                "AES_192/CFB/NoPadding",
                "AES_192/ECB/NoPadding",
                "AES_192/GCM/NoPadding",
                "AES_192/KW/NoPadding",
                "AES_192/KWP/NoPadding",
                "AES_192/OFB/NoPadding",
                "AES_256/CBC/PKCS5Padding",
                "AES_256/CFB/NoPadding",
                "AES_256/ECB/NoPadding",
                "AES_256/GCM/NoPadding",
                "AES_256/KW/NoPadding",
                "AES_256/KWP/NoPadding",
                "AES",
                "AES/GCM/NoPadding",
                "AES/KW/NoPadding",
                "AES/KWP/NoPadding",
                "DESede",
                "DESede/CBC/PKCS5Padding",
                "PBEWithHmacSHA1AndAES_128",
                "PBEWithHmacSHA1AndAES_256",
                "PBEWithHmacSHA224AndAES_128",
                "PBEWithHmacSHA224AndAES_256",
                "PBEWithHmacSHA256AndAES_128",
                "PBEWithHmacSHA256AndAES_256",
                "PBEWithHmacSHA384AndAES_128",
                "PBEWithHmacSHA384AndAES_256",
                "PBEWithHmacSHA512AndAES_128",
                "PBEWithHmacSHA512AndAES_256",
                "RSA/ECB/OAEPPadding",
                "RSA/ECB/OAEPWithSHA-1andMGF1Padding",
                "RSA/ECB/OAEPWithSHA-224andMGF1Padding",
                "RSA/ECB/OAEPWithSHA-256andMGF1Padding",
                "RSA/ECB/OAEPWithSHA-384andMGF1Padding",
                "RSA/ECB/OAEPWithSHA-512andMGF1Padding"
        });
        serviceAlgorithms.put("KDF", new String[]{"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512"});

        serviceAlgorithms.put("KEM", new String[]{"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"});

        serviceAlgorithms.put("KeyAgreement", new String[]{"DH", "ECDH"});

        serviceAlgorithms.put("KeyFactory", new String[]{"DH", "DSA", "EC",
                "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "RSA", "RSASSA-PSS"});

        serviceAlgorithms.put("KeyGenerator", new String[]{
                "AES_128/CBC/PKCS5Padding",
                "AES_128/CFB/NoPadding",
                "AES_128/ECB/NoPadding",
                "AES_128/GCM/NoPadding",
                "AES_128/OFB/NoPadding",
                "AES_192/CBC/PKCS5Padding",
                "AES_192/CFB/NoPadding",
                "AES_192/ECB/NoPadding",
                "AES_192/GCM/NoPadding",
                "AES_192/OFB/NoPadding",
                "AES_256/CBC/PKCS5Padding",
                "AES_256/CFB/NoPadding",
                "AES_256/ECB/NoPadding",
                "AES_256/GCM/NoPadding",
                "AES_256/OFB/NoPadding",
                "AES",
                "HmacSHA1",
                "HmacSHA224",
                "HmacSHA256",
                "HmacSHA384",
                "HmacSHA512",
                "SunTls12Prf",
                "SunTlsKeyMaterial",
                "SunTlsExtendedMasterSecret",
                "SunTlsRsaPremasterSecret"
        });

        serviceAlgorithms.put("KeyPairGenerator", new String[]{"DH", "EC",
                "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "RSA", "RSASSA-PSS"});

        serviceAlgorithms.put("Mac", new String[]{
                "HmacSHA1",
                "HmacSHA224",
                "HmacSHA256",
                "HmacSHA384",
                "HmacSHA512"
        });

        serviceAlgorithms.put("MessageDigest", new String[]{"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"});
        serviceAlgorithms.put("SecretKeyFactory", new String[]{
                "AES",
                "DESede",
                "PBE",
                "PBES2",
                "PBEWithHmacSHA1AndAES_128",
                "PBEWithHmacSHA1AndAES_256",
                "PBEWithHmacSHA224AndAES_128",
                "PBEWithHmacSHA224AndAES_256",
                "PBEWithHmacSHA256AndAES_128",
                "PBEWithHmacSHA256AndAES_256",
                "PBEWithHmacSHA384AndAES_128",
                "PBEWithHmacSHA384AndAES_256",
                "PBEWithHmacSHA512AndAES_128",
                "PBEWithHmacSHA512AndAES_256",
                "PBKDF2WithHmacSHA1",
                "PBKDF2WithHmacSHA1and8BIT",
                "PBKDF2WithHmacSHA224",
                "PBKDF2WithHmacSHA224and8BIT",
                "PBKDF2WithHmacSHA256",
                "PBKDF2WithHmacSHA256and8BIT",
                "PBKDF2WithHmacSHA384",
                "PBKDF2WithHmacSHA384and8BIT",
                "PBKDF2WithHmacSHA512",
                "PBKDF2WithHmacSHA512and8BIT"
        });
        serviceAlgorithms.put("SecureRandom", new String[]{"DRBG"});

        serviceAlgorithms.put("Signature", new String[]{
                "ML-DSA",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "NONEwithDSA",
                "NONEwithECDSA",
                "NONEwithRSA",
                "MD5withRSA",
                "RSASSA-PSS",
                "SHA1withDSA",
                "SHA1withECDSA",
                "SHA1withRSA",
                "SHA1withRSAandMGF1",
                "SHA224withDSA",
                "SHA224withECDSA",
                "SHA224withRSA",
                "SHA224withRSAandMGF1",
                "SHA256withDSA",
                "SHA256withECDSA",
                "SHA256withRSA",
                "SHA256withRSAandMGF1",
                "SHA384withDSA",
                "SHA384withECDSA",
                "SHA384withRSA",
                "SHA384withRSAandMGF1",
                "SHA512withDSA",
                "SHA512withECDSA",
                "SHA512withRSA",
                "SHA512withRSAandMGF1"
        });

        SERVICE_ALGORITHMS = serviceAlgorithms;
    }

    @Test
    public void constructor() {
        try (MockedStatic<OpenSslValidator> MockOpenSslValidator = Mockito.mockStatic(OpenSslValidator.class)) {
            MockOpenSslValidator.when(OpenSslValidator::isAvailable).thenReturn(true);
            try (MockedStatic<OpenSslVersion> MockOpenSslVersion = Mockito.mockStatic(OpenSslVersion.class)) {
                MockOpenSslVersion.when(OpenSslVersion::get).thenReturn(TEST_CRYPTO_VERSION);
                try (MockedStatic<FipsProviderInfo> MockFipsProviderInfo = Mockito.mockStatic(FipsProviderInfo.class)) {
                    MockFipsProviderInfo.when(FipsProviderInfo::getNameString).thenReturn(TEST_FIPS_PROVIDER_NAME);
                    MockFipsProviderInfo.when(FipsProviderInfo::getVersionString).thenReturn(
                            TEST_FIPS_PROVIDER_VERSION);

                    new JipherJCE();

                    MockOpenSslValidator.verify(OpenSslValidator::isAvailable, Mockito.times(1));
                }
            }
        }
    }

    @Test
    public void getInfo() {
        try (MockedStatic<OpenSslValidator> MockOpenSslValidator = Mockito.mockStatic(OpenSslValidator.class)) {
            MockOpenSslValidator.when(OpenSslValidator::isAvailable).thenReturn(true);
            try (MockedStatic<OpenSslVersion> MockOpenSslVersion = Mockito.mockStatic(OpenSslVersion.class)) {
                MockOpenSslVersion.when(OpenSslVersion::get).thenReturn(TEST_CRYPTO_VERSION);
                try (MockedStatic<FipsProviderInfo> MockFipsProviderInfo = Mockito.mockStatic(FipsProviderInfo.class)) {
                    MockFipsProviderInfo.when(FipsProviderInfo::getNameString).thenReturn(TEST_FIPS_PROVIDER_NAME);
                    MockFipsProviderInfo.when(FipsProviderInfo::getVersionString).thenReturn(TEST_FIPS_PROVIDER_VERSION);

                    String info = new JipherJCE().getInfo();

                    assertTrue(info.startsWith("JipherJCE Provider"));
                    assertTrue(info.contains(TEST_CRYPTO_VERSION +
                            " with " + TEST_FIPS_PROVIDER_NAME + " version " + TEST_FIPS_PROVIDER_VERSION));
                }
            }
        }
    }

    @Test
    public void infoWithoutOpenSSLVersion() {
        // Tests that the OpenSSL interface is not used when JipherJCE.info(false) is called
        final boolean[] getInstanceCalled = new boolean[1];
        OpenSsl mockOpenSsl = mock(OpenSsl.class);
        try (MockedStatic<OpenSsl> MockOpenSsl = Mockito.mockStatic(OpenSsl.class)) {
            MockOpenSsl.when(OpenSsl::getInstance).then(x -> {getInstanceCalled[0] = true; return mockOpenSsl;});

            JipherJCE.info(false);

            assertFalse(getInstanceCalled[0]);
        }
    }

    @Test
    public void mainFailsGracefullyWhenOpenSSLVersionInformationUnavailable() {
        try (MockedStatic<OpenSslVersion> MockOpenSslVersion = Mockito.mockStatic(OpenSslVersion.class)) {
            MockOpenSslVersion.when(OpenSslVersion::get).thenThrow(new ProviderException("Test Exception"));

            PrintStream stdout = System.out;
            PrintStream stderr = System.err;
            try {
                OutputStream outStream = new ByteArrayOutputStream();
                OutputStream errStream = new ByteArrayOutputStream();

                System.setOut(new PrintStream(outStream));
                System.setErr(new PrintStream(errStream));

                JipherJCE.main(null);

                final String stdOutContent = outStream.toString();
                final String stdErrContent = errStream.toString();

                assertTrue(stdOutContent.startsWith("JipherJCE Provider"));
                assertTrue(stdErrContent.startsWith("OpenSSL version information unavailable due to"));
                assertTrue(stdErrContent.contains("Test Exception"));
            } finally {
                System.setOut(stdout);
                System.setErr(stderr);
            }
        }
    }

    @Test
    public void getName() {
        assertEquals("JipherJCE",  new JipherJCE().getName());
    }

    @Test
    public void getVersion() {
        assertFalse(new JipherJCE().getVersionStr().isEmpty());
    }

    @Test
    public void serviceAlgorithmRegistrationWithFipsProviderCapabilities()
    {
        for (int index = 0; index < (1 << 5); index++) {
            testServiceAlgorithmRegistrationWithFipsProviderCapabilities(index);
        }
    }

    private void testServiceAlgorithmRegistrationWithFipsProviderCapabilities(int index) {
        boolean isDESEDESupported                  = (index & (1 << 0)) != 0;
        boolean isDSASupported                     = (index & (1 << 1)) != 0;
        boolean isSHA1DigestSignatureSupported     = (index & (1 << 2)) != 0;
        boolean isMLDSASupported                   = (index & (1 << 3)) != 0;
        boolean isMLKEMSupported                   = (index & (1 << 4)) != 0;

        try (MockedStatic<Capabilities> MockCapabilities = Mockito.mockStatic(Capabilities.class)) {
            MockCapabilities.when(Capabilities::isDESEDESupported).thenReturn(isDESEDESupported);
            MockCapabilities.when(Capabilities::isDSASupported).thenReturn(isDSASupported);
            MockCapabilities.when(Capabilities::isSHA1DigestSignatureSupported).thenReturn(isSHA1DigestSignatureSupported);
            MockCapabilities.when(Capabilities::isMlDsaSupported).thenReturn(isMLDSASupported);
            MockCapabilities.when(Capabilities::isMlKemSupported).thenReturn(isMLKEMSupported);

            testServiceAlgorithmRegistration(isDESEDESupported, isDSASupported, isSHA1DigestSignatureSupported,
                    isMLDSASupported, isMLKEMSupported);
        }
    }

    @Test
    public void testServiceAlgorithmRegistrationWithFipsStrictPolicy() {
        try (MockedStatic<Capabilities> MockCapabilities = Mockito.mockStatic(Capabilities.class)) {
            MockCapabilities.when(Capabilities::isDESEDESupported).thenReturn(true);
            MockCapabilities.when(Capabilities::isDSASupported).thenReturn(true);
            MockCapabilities.when(Capabilities::isSHA1DigestSignatureSupported).thenReturn(true);
            MockCapabilities.when(Capabilities::isMlDsaSupported).thenReturn(true);
            MockCapabilities.when(Capabilities::isMlKemSupported).thenReturn(true);

            try (MockedStatic<ToolkitProperties> MockToolkitProperties = Mockito.mockStatic(ToolkitProperties.class)) {
                MockToolkitProperties.when(ToolkitProperties::getFipsEnforcementValue).thenReturn(Fips.EnforcementPolicy.FIPS_STRICT);
                // Need to mock this as well, as the static mocking would otherwise pick-up default value (null) of the variable
                MockToolkitProperties.when(ToolkitProperties::getJavaRuntimeVersionValue).thenReturn(System.getProperty("java.runtime.version"));
                MockToolkitProperties.when(ToolkitProperties::getJavaVendorValue).thenReturn(System.getProperty("java.vendor"));

                testServiceAlgorithmRegistration(false, false, false, true, true);
            }
        }
    }

    private static void testServiceAlgorithmRegistration(
                        boolean isDESEDESupported, boolean isDSASupported, boolean isSHA1DigestSignatureSupported,
                        boolean isMLDSSASupported, boolean isMLKEMSupported) {

        Provider provider = new JipherJCE();

        for (String service : SERVICE_ALGORITHMS.keySet()) {
            for (String algorithm : SERVICE_ALGORITHMS.get(service)) {
                boolean registrationExpected = isRegistrationExpected(service, algorithm,
                        isDESEDESupported, isDSASupported, isSHA1DigestSignatureSupported,
                        isMLDSSASupported, isMLKEMSupported);

                String message = service + "." + algorithm + " should " +
                        (registrationExpected ? "" : "not ") + "be registered when " +
                        "DESEDE is " + (isDESEDESupported ? "" : "not ") + "supported, " +
                        "DSA is " + (isDSASupported ? "" : "not ") + "supported, " +
                        "SHA1 Digest Signatures are " + (isSHA1DigestSignatureSupported ? "" : "not ") + "supported, " +
                        "ML-DSA is " + (isMLDSSASupported ? "" : "not ") + "supported, " +
                        "ML-KEM is " + (isMLKEMSupported ? "" : "not ") + "supported";

                Provider.Service s = provider.getService(service, algorithm);
                if (registrationExpected) {
                    assertNotNull(message, s);
                } else {
                    assertNull(message, s);
                }
            }
        }
    }

    private static boolean isRegistrationExpected(String service, String algorithm,
                        boolean isDESEDESupported, boolean isDSASupported, boolean isSHA1DigestSignatureSupported,
                        boolean isMLDSASupported, boolean isMLKEMSupported) {

        boolean registrationExpected = true;

        if (service.equals("Signature") && algorithm.equalsIgnoreCase("MD5withRSA")) {
            try {
                registrationExpected = ToolkitProperties.getJavaVendorValue().startsWith("Oracle") &&
                        EnvUtil.getJavaRuntimeMajorVersion() < 26;
            } catch (ParseException e) {
                registrationExpected = false;
            }
        }

        if (service.equalsIgnoreCase("KDF")) {
            try {
                registrationExpected = (EnvUtil.getJavaRuntimeMajorVersion() >= 25);
            } catch (ParseException e) {
                registrationExpected = false;
            }
        }

        if (!isDESEDESupported) {
            if (algorithm.toLowerCase().contains("DESede".toLowerCase())) {
                registrationExpected = false;
            }
        }

        if (!isDSASupported) {
            if (algorithm.toLowerCase().contains("DSA".toLowerCase()) &&
                    !(algorithm.toLowerCase().contains("ECDSA".toLowerCase()) || algorithm.toLowerCase().contains("ML-DSA".toLowerCase()))) {
                registrationExpected = false;
            }
        }

        if (!isMLDSASupported) {
            if (algorithm.toLowerCase().contains("ML-DSA".toLowerCase())) {
                registrationExpected = false;
            }
        }

        if (!isMLKEMSupported) {
            if (algorithm.toLowerCase().contains("ML-KEM".toLowerCase())) {
                registrationExpected = false;
            }
        }

        if (!isSHA1DigestSignatureSupported) {
            if (service.equals("Signature")) {
                if (algorithm.toLowerCase().startsWith("Sha1With".toLowerCase())) {
                    try {
                        registrationExpected = algorithm.equalsIgnoreCase("SHA1withECDSA") &&
                                EnvUtil.getJavaRuntimeMajorVersion() < 27;
                    } catch (ParseException e) {
                        registrationExpected = false;
                    }
                }
            }
        }

        return registrationExpected;
    }
}
