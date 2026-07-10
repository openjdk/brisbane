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

package com.oracle.systest.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.helpers.ProviderSetup;
import com.oracle.jiphertest.helpers.TlsServer;
import com.oracle.jiphertest.helpers.TlsSetup;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;

import static com.oracle.jiphertest.helpers.TlsSetup.genTestData;
import static com.oracle.jiphertest.helpers.TlsSetup.readData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

@RunWith(Parameterized.class)
public class TlsSystemTest {

    static final int TESTDATA_SIZE = 36 * 1024;

    static SSLSocketFactory sf;
    static byte[] testData;
    static TlsSetup.ProviderConfig cfg;

    static {
        cfg = getProviderConfig(System.getProperty("security.config.client"));
        if (cfg == TlsSetup.ProviderConfig.JIPHER_JSSE) {
            // Limit the list of registered security providers to those required to support a TLS stack
            List<String> requiredProviderNames = new ArrayList<>(List.of("JipherJCE", "SUN", "SunJSSE"));
            String namedGroups = System.getProperty("jdk.tls.namedGroups");
            if (namedGroups != null && namedGroups.toUpperCase().contains("X25519MLKEM768")) {
                // SunEC is required to provide X25519 component of X25519MLKEM768
                requiredProviderNames.add("SunEC");
            }
            ProviderSetup.limitProviders(requiredProviderNames);
        }
    }

    @Parameterized.Parameters(name = "{0},proto={1},ciphersuite={2}")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> all = new ArrayList<>();

        String namedGroups = System.getProperty("jdk.tls.namedGroups");
        if (namedGroups == null || !namedGroups.toUpperCase().contains("MLKEM")) {
            // TLS 1.2 ECDHE does not require the ephemeral ECDHE group to match the
            // ECDSA certificate curve. However, JSSE checks the EC certificate curve
            // against the configured named groups for TLS 1.2 and earlier.
            // The TLS test PKI includes server certificates for SecP256r1,
            // SecP384r1 and SecP521r1 to allow testing these named groups for TLS 1.2.

            for (String cs : TlsSetup.ciphersuitesV12()) {
                all.add(new Object[]{getProviderConfigID(), "TLSv1.2", cs});
            }
        }

        for (String cs : TlsSetup.ciphersuitesV13()) {
            all.add(new Object[] {getProviderConfigID(), "TLSv1.3",cs});
        }
        return all;
    }

    private static String getProviderConfigID() {
        return "client=" + cfg + ",server=" + getServerConfig();
    }

    private static TlsSetup.ProviderConfig getProviderConfig(String configValue) {
        if ("Pos1".equalsIgnoreCase(configValue)) {
            return TlsSetup.ProviderConfig.JIPHER_JSSE;
        }
        return TlsSetup.ProviderConfig.JDK_JSSE;
    }

    private static TlsSetup.ProviderConfig getServerConfig() {
        return getProviderConfig(System.getProperty("security.config.server"));
    }

    String protocolVersion;
    String cipherSuite;

    static TlsServer server;
    static TlsServer serverClientAuth;

    @BeforeClass
    public static void setUp() throws Exception {

        // Only test with MLKEM named groups if the OpenSSL FIPS provider
        // that Jipher will use during the test supports MLKEM
        if (System.getProperty("jdk.tls.namedGroups", "").toUpperCase().contains("MLKEM")) {
            assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        }

        testData = genTestData(TESTDATA_SIZE);
        server = new TlsServer(getServerConfig(), false);
        serverClientAuth = new TlsServer(getServerConfig(), true);
        server.startServer();
        serverClientAuth.startServer();

        SSLContext ctx = TlsSetup.getSSLContext("client");
        sf = ctx.getSocketFactory();
    }

    public TlsSystemTest(String configId, String protocolVer, String cipherSuite) {
        this.protocolVersion = protocolVer;
        this.cipherSuite = cipherSuite;
    }

    @Test
    public void serverAuth() throws Exception {
        doTest(server);
    }

    @Test
    public void clientAuth() throws Exception {
        doTest(serverClientAuth);
    }

    public void doTest(TlsServer server) throws Exception {
        SSLSocket s = (SSLSocket)sf.createSocket("localhost", server.getPort());
        if (this.protocolVersion.equals("TLSv1.3")) {
            assumeTrue("TLSv1.3 not supported", Arrays.asList(s.getSupportedProtocols()).contains("TLSv1.3"));
        }
        s.setEnabledProtocols(new String[] {this.protocolVersion});
        s.setEnabledCipherSuites(new String[] {this.cipherSuite});
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        os.write(testData);
        os.flush();
        byte[] receivedData = readData(is, TESTDATA_SIZE);
        s.close();
        SSLSession session = s.getSession();
        checkCipherSuite(this.cipherSuite, session.getCipherSuite());
        assertTrue(server.getResult());
        assertArrayEquals(testData, receivedData);
    }

    private void checkCipherSuite(String cipherSuite, String sessionSuite) {
        assertEquals(cipherSuite.substring(4), sessionSuite.substring(4));
    }

    @AfterClass
    public static void stopServers() throws InterruptedException {
        if (server != null) {
            server.stopServer();
        }
        if (serverClientAuth != null) {
            serverClientAuth.stopServer();
        }
    }

}
