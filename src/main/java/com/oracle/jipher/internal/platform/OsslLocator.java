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

package com.oracle.jipher.internal.platform;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.ProviderException;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.oracle.jipher.internal.common.ToolkitProperties;

public class OsslLocator {
    private static final Platform THIS_PLATFORM = Platform.getPlatform();
    private static final Path OPENSSL_DIR_PATH = ToolkitProperties.getOpenSslDirValue() != null ?
            Paths.get(ToolkitProperties.getOpenSslDirValue()) : THIS_PLATFORM.getOpensslPath();
    private static final String[] LIB_DIR_VARIANTS = new String[]{"lib64", "lib", "bin"};
    private static final String[] CNF_FILENAME_VARIANTS = new String[]{"fipsmodule.cnf", "openssl.cnf"};

    private static final Pattern FIPS_MODULE_MAC_PATTERN = Pattern.compile("^\\s*module-mac\\s*=\\s*(\\S+)\\s*$");
    private static final String NOT_SUPPORTED_PREFIX = "Use of operating system provided instance of OpenSSL is not supported for ";

    private static <T> T fromLinuxDistro(Function<LinuxDistro, T> getter) {
        try {
            LinuxDistro linuxDistro = LinuxDistro.getLinuxDistro();
            if (linuxDistro.providesFipsModule()) {
                return getter.apply(linuxDistro);
            }
            throw new ProviderException(NOT_SUPPORTED_PREFIX + linuxDistro);
        } catch (UnrecognisedLinuxDistroException e) {
            throw new ProviderException(NOT_SUPPORTED_PREFIX + "Linux distribution " + e.getMessage());
        }
    }

    /**
     * Get the path to the OpenSSL cryptography library (libcrypto)
     * @return the path to the OpenSSL cryptography library
     * @throws ProviderException if the OpenSSL cryptography library cannot be located
     */
    public static Path getCryptoLibPath() {
        if (ToolkitProperties.getOpenSSLUseOsInstanceValue()) {
            if (THIS_PLATFORM instanceof Platform.Linux) {
                return fromLinuxDistro(LinuxDistro::getCryptoLibPath);
            }
            throw new ProviderException(NOT_SUPPORTED_PREFIX + THIS_PLATFORM);
        } else {
            for (String libDir : LIB_DIR_VARIANTS) {
                for (String cryptoLibFilename : THIS_PLATFORM.getCryptoLibFilenames()) {
                    Path path = OPENSSL_DIR_PATH.resolve(Paths.get(libDir, cryptoLibFilename));
                    if (Files.exists(path) && Files.isExecutable(path) && !Files.isDirectory(path)) {
                        return path;
                    }
                }
            }
            throw new ProviderException("OpenSSL crypto library path not found");
        }
    }

    /**
     * Get the OpenSSL provider search path.
     * @return the path to search for OpenSSL providers on
     * @throws ProviderException if the OpenSSL provider search path can not be identified
     */
    public static Path getProviderSearchPath() {
        if (ToolkitProperties.getOpenSSLUseOsInstanceValue()) {
            if (THIS_PLATFORM instanceof Platform.Linux) {
                return fromLinuxDistro(LinuxDistro::getProviderSearchPath);
            }
            throw new ProviderException(NOT_SUPPORTED_PREFIX + THIS_PLATFORM);
        } else {
            for (String libDir : LIB_DIR_VARIANTS) {
                Path path = OPENSSL_DIR_PATH.resolve(Paths.get(libDir, "ossl-modules"));
                if (Files.exists(path) && Files.isDirectory(path)) {
                    return path;
                }
            }
            throw new ProviderException("OpenSSL provider search path not found.");
        }
    }

    private static String readFipsModuleMacFromFile() {
        Exception lastException = null;
        for (String filename : CNF_FILENAME_VARIANTS) {
            Path path = OPENSSL_DIR_PATH.resolve(Paths.get("ssl", filename));
            if (Files.exists(path) && !Files.isDirectory(path)) {
                try (BufferedReader reader = Files.newBufferedReader(path)) {
                    Optional<String> mac = reader.lines().map(FIPS_MODULE_MAC_PATTERN::matcher).filter(Matcher::matches).findFirst()
                            .map(matcher -> matcher.group(1));
                    if (mac.isPresent()) {
                        return mac.get();
                    }
                } catch (IOException e) {
                    lastException = e;
                }
            }
        }
        if (lastException != null) {
            throw new ProviderException("OpenSSL FIPS module mac not found", lastException);
        } else {
            throw new ProviderException("OpenSSL FIPS module mac not found");
        }
    }

    /**
     * Get the OpenSSL FIPS module MAC.
     * @return the OpenSSL FIPS module MAC, or null if the module MAC is embedded as a data element in the FIPS module
     * @throws ProviderException if the OpenSSL FIPS module MAC cannot be determined,
     *                           and it is not embedded as a data element in the FIPS module
     */
    public static String getFipsModuleMac() {
        if (ToolkitProperties.getOpenSSLUseOsInstanceValue()) {
            if (THIS_PLATFORM instanceof Platform.Linux) {
                return fromLinuxDistro(LinuxDistro::getFipsModuleMac);
            }
            throw new ProviderException("Use of operating system provided instance of OpenSSL " +
                    "is not supported for platform " + THIS_PLATFORM);
        } else {
            return readFipsModuleMacFromFile();
        }
    }
}
