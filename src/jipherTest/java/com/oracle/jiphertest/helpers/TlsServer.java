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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import com.oracle.jiphertest.util.EnvUtil;

import static com.oracle.jiphertest.helpers.TlsSetup.readData;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class TlsServer {

    static final int MIN_PORT = 3320;
    static final int MAX_PORT = 3359;
    static final int TESTDATA_SIZE = 36 * 1024;

    Process serverProcess;
    BufferedReader serverBR;

    private final TlsSetup.ProviderConfig cfg;
    private final boolean clientAuth;
    private int port;
    public TlsServer(TlsSetup.ProviderConfig cfg, boolean clientAuth) {
        this.cfg = cfg;
        this.clientAuth = clientAuth;
    }

    public int getPort() {
        return this.port;
    }

    private String getJavaSecurityFile() throws Exception {
        if (this.cfg == TlsSetup.ProviderConfig.JDK_JSSE) {
            return "";
        }

        Path p = Files.createTempFile("jipher", ".java.security");
        p.toFile().deleteOnExit();
        InputStream ris = TlsServer.class.getResourceAsStream("java.security/" + this.cfg + ".java.security");
        Files.copy(ris, p, REPLACE_EXISTING);
        return p.toAbsolutePath().toString();
    }

    private static String removeJipherModule(String modulePath) {
        if (modulePath == null) {
            return null;
        } else {
            modulePath =  Arrays.stream(modulePath.split(File.pathSeparator))
                    .filter(s -> !s.matches(".*jipher-jce-[0-9]+(\\.[0-9]+)*\\.jar"))
                    .collect(Collectors.joining(File.pathSeparator));

            // Having removed the 'com.oracle.jipher' module we must
            // also remove the 'com.oracle.jiphertest.integration' module
            // which requires the 'com.oracle.jipher' module
            modulePath =  Arrays.stream(modulePath.split(File.pathSeparator))
                    .filter(s -> !s.matches(".*build.classes.java.intTest"))
                    .collect(Collectors.joining(File.pathSeparator));

            return modulePath;
        }
    }

    public void startServer() throws Exception {
        String modulepath = System.getProperty("jdk.module.path");
        String classpath = System.getProperty("java.class.path");
        String javahome = System.getProperty("java.home");

        // If the name-separator character is backslash then ensure name-separators in the module path
        // or class path have not been unnecessarily duplicated.
        if (File.separatorChar == '\\') {
            if (modulepath != null) {
                // Replace duplicate name-separator characters with a single name-separator character.
                modulepath = modulepath.replace(File.separator + File.separator, File.separator);
            }
            if (classpath != null) {
                // Replace duplicate name-separator characters with a single name-separator character.
                classpath = classpath.replace(File.separator + File.separator, File.separator);
            }
        }

        int javaRuntimeMajorVersion = EnvUtil.getJavaRuntimeMajorVersion();

        if (this.cfg == TlsSetup.ProviderConfig.JDK_JSSE) {
            // Remove com.oracle.jipher module from the module path.
            // This ensures that the JipherJCE provider will not be trial loaded by the service loader
            // and trigger a restricted method access warning related to accessing native code
            modulepath = removeJipherModule(modulepath);
        }

        List<String> command = new ArrayList<>();
        command.add(javahome + File.separator + "bin" + File.separator + "java");
        if (modulepath != null) {
            command.addAll(List.of("--module-path", modulepath, "--add-modules", "ALL-MODULE-PATH"));
        }
        if (classpath != null) {
            command.addAll(List.of("--class-path", classpath));
        }
        command.addAll(List.of(
                "-Djdk.tls.ephemeralDHKeySize=2048",
                "-Djava.security.properties=" + getJavaSecurityFile(),
                TlsServer.class.getName(), this.cfg.name(), String.valueOf(this.clientAuth)));

        String jipherModuleName  = (modulepath != null) ? "com.oracle.jipher" : "ALL-UNNAMED";
        String jipherTestModuleName = (modulepath != null) ? "com.oracle.jiphertest.other" : "ALL-UNNAMED";

        if (this.cfg == TlsSetup.ProviderConfig.JIPHER_JSSE) {
            // Forward jipher related system property settings to the server JVM
            System.getProperties().stringPropertyNames().stream().filter(key -> key.startsWith("jipher")).forEach(
                    key -> command.add(1, "-D" + key + "=" + System.getProperty(key)));

            // From JDK 9 onward internal JDK APIs are no longer accessible by default
            command.add(1, "--add-exports=java.base/sun.security.internal.spec=" + jipherModuleName);

            // SunJSSE uses RawKeySpec to pass the key share into KeyFactory.generatePublic(KeySpec).
            // This is required for Jipher to be able to access sun.security.util.RawKeySpec.
            // (Without access, Jipher may fall back to SunJCE if it is registered or otherwise fail the handshake.)
            command.add(1, "--add-exports=java.base/sun.security.util=" + jipherModuleName);

            // com.oracle.jiphertest.util.X509FactoryUtil.class needs access to sun.security.provider.X509Factory
            command.add(1, "--add-exports=java.base/sun.security.provider=" + jipherTestModuleName);

            if (javaRuntimeMajorVersion >= 22) {
                // Suppress restricted method warnings related to accessing methods considered to be unsafe.
                // See https://docs.oracle.com/en/java/javase/25/core/restricted-methods.html
                command.add(1, "--enable-native-access=" + jipherModuleName);
            }
        }
        if (System.getProperty("jdk.tls.namedGroups") != null) {
            command.add(1, "-Djdk.tls.namedGroups=" + System.getProperty("jdk.tls.namedGroups"));
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        serverProcess = pb.start();
        serverBR = new BufferedReader(new InputStreamReader(serverProcess.getInputStream()));
        try {
            port = Integer.parseInt(serverBR.readLine().trim());
        } catch (NumberFormatException e) {
            // Ignore - this can happen when the server is run with -agentlib:jdwp
            port = Integer.parseInt(serverBR.readLine().trim());
        }
        assertNotEquals(-1, port);
    }

    public void stopServer() throws InterruptedException {
        if (serverProcess == null) {
            System.err.println("Cannot stop server, process was null.");
            return;
        }
        if (serverProcess.isAlive()) {
            serverProcess.destroy();
        }
        if (!serverProcess.waitFor(5, TimeUnit.SECONDS)) {
            System.err.println("Forcibly killing TLS server");
            serverProcess.destroyForcibly();
        }
        serverProcess = null;
        serverBR = null;
    }

    public boolean getResult() throws IOException {
        return Boolean.parseBoolean(serverBR.readLine().trim());
    }

    private static void runServer(SSLServerSocket ss, boolean clientAuth) throws Exception {
        if (Arrays.asList(ss.getEnabledProtocols()).contains("TLSv1.3")) {
            ss.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        } else {
            ss.setEnabledProtocols(new String[] {"TLSv1.2"});
        }
        ss.setNeedClientAuth(clientAuth);
        for (;;) {
            System.out.flush();
            SSLSocket s = (SSLSocket)ss.accept();
            try {
                InputStream is = s.getInputStream();
                OutputStream os = s.getOutputStream();
                byte[] receivedData = readData(is, TESTDATA_SIZE);
                os.write(receivedData);
                s.close();
            } catch (Throwable t) {
                t.printStackTrace();
                System.out.println(false);
                continue;
            }
            System.out.println(true);
        }
    }

    // Server
    public static void main(String[] args) throws Exception {
        TlsSetup.ProviderConfig cfg = TlsSetup.ProviderConfig.valueOf(args[0]);
        boolean clientAuth = Boolean.parseBoolean(args[1]);
        if (cfg == TlsSetup.ProviderConfig.JDK_JSSE) {
            assertNull(Security.getProvider("JipherJCE"));
        } else {
            // Limit the list of registered security providers to those required to support a TLS stack
            List<String> requiredProviderNames = new ArrayList<>(List.of("JipherJCE", "SUN", "SunJSSE"));
            String namedGroups = System.getProperty("jdk.tls.namedGroups");
            if (namedGroups != null && namedGroups.toUpperCase().contains("X25519MLKEM768")) {
                // SunEC is required to provide X25519 component of X25519MLKEM768
                requiredProviderNames.add("SunEC");
            }
            ProviderSetup.limitProviders(requiredProviderNames);
            assertNotNull(Security.getProvider("JipherJCE"));
        }
        SSLContext ctx = TlsSetup.getSSLContext("server");
        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        for (int port = MIN_PORT; port <= MAX_PORT; ++port) {
            SSLServerSocket ss;
            try {
                ss = (SSLServerSocket)ssf.createServerSocket(port);
            } catch (IOException e) {
                continue;
            }
            System.out.println(port);
            runServer(ss, clientAuth);
            return;
        }
        System.err.println("Could not bind server socket");
        System.out.println(-1);
        System.exit(1);
    }
}
