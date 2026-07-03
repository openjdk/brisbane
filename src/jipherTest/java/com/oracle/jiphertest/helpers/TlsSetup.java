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

package com.oracle.jiphertest.helpers;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;

public class TlsSetup {

    public enum ProviderConfig {
        JDK_JSSE,
        JIPHER_JSSE
    }

    static final char[] PASSPHRASE = "Password1".toCharArray();
    static final String KS_TYPE = "PKCS12";
    static final String KS_EXT = ".p12";

    public static SSLContext getSSLContext(String endpointType) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance(KS_TYPE);
        KeyStore ts = KeyStore.getInstance(KS_TYPE);

        // PKCS#12 KeyStore support for RFC 9879 was first added in JDK 26
        String directory = (EnvUtil.getJavaRuntimeMajorVersion() < 26) ? "/pki/nomac/" : "/pki/";
        ks.load(TestData.getResourceAsStream(directory + endpointType + KS_EXT), PASSPHRASE);
        ts.load(TestData.getResourceAsStream(directory + endpointType + "trust" + KS_EXT), PASSPHRASE);
        kmf.init(ks, PASSPHRASE);
        tmf.init(ts);
        ctx.init(getKeyManagers(endpointType, kmf), tmf.getTrustManagers(), null);
        return ctx;
    }

    private static KeyManager[] getKeyManagers(String endpointType, KeyManagerFactory kmf) {
        // Clients and most server configurations use the default key managers. When a
        // server test restricts jdk.tls.namedGroups to one EC group, force JSSE to use
        // the matching EC server certificate alias from server.p12.
        // (For TLS 1.2 and earlier, JSSE checks the EC certificate curve against
        // jdk.tls.namedGroups. If the default key manager chooses an EC certificate
        // with a different curve, SunJSSE reports "no cipher suites in common".)
        KeyManager[] keyManagers = kmf.getKeyManagers();
        String namedGroups = System.getProperty("jdk.tls.namedGroups");
        String ecAlias = null;
        if (namedGroups != null) {
            ecAlias = switch (namedGroups.toLowerCase()) {
                case "secp256r1" -> "ec_p256_server";
                case "secp384r1" -> "ec_p384_server";
                case "secp521r1" -> "ec_p521_server";
                default -> null;
            };
        }

        // Override server EC alias selection to force the required certificate.
        if ("server".equals(endpointType) && ecAlias != null) {
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof X509ExtendedKeyManager keyManager) {
                    keyManagers[i] = new ServerEcAliasKeyManager(keyManager, ecAlias);
                }
            }
        }

        return keyManagers;
    }

    private static final class ServerEcAliasKeyManager extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager akm;
        private final String ecAlias;

        private ServerEcAliasKeyManager(X509ExtendedKeyManager akm, String ecAlias) {
            this.akm = akm;
            this.ecAlias = ecAlias;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return akm.getClientAliases(keyType, issuers);
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return akm.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            if (isEcKeyType(keyType)) {
                return ecAlias;
            }
            return akm.chooseServerAlias(keyType, issuers, socket);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return akm.getServerAliases(keyType, issuers);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return akm.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return akm.getPrivateKey(alias);
        }

        private static boolean isEcKeyType(String keyType) {
            return keyType != null && keyType.equals("EC");
        }
    }

    public static byte[] readData(InputStream is, int n) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        byte[] buf = new byte[n];
        dis.readFully(buf);
        return buf;
    }

    public static byte[] genTestData(int size) {
        byte[] b = new byte[size];
        Random r = new Random();
        r.setSeed(1234L);
        r.nextBytes(b);
        return b;
    }

    private static boolean supported(String cipherSuite)
    {
        for (String algorithm : TlsConstraints.decomposeCipherSuite(cipherSuite)) {
            if (!FipsProviderInfoUtil.isDSASupported() && "DSS".equals(algorithm)) {
                return false;
            }
        }
        return true;
    }

    public static List<String> ciphersuitesV13() {
        return Stream.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384").
                filter(TlsConstraints::permitted).filter(TlsSetup::supported).collect(Collectors.toList());
    }

    public static List<String> ciphersuitesV12Subset() {
        return Stream.of(
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",

                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",

                "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",

                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",

                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",

                "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
                ).filter(TlsConstraints::permitted).filter(TlsSetup::supported).collect(Collectors.toList());
    }

    public static List<String> ciphersuitesV12() {
        return Stream.of(
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
            ).filter(TlsConstraints::permitted).filter(TlsSetup::supported).collect(Collectors.toList());
    }
}
