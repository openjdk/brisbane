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

import java.nio.file.Path;
import java.nio.file.Paths;

import com.oracle.jipher.internal.common.ToolkitProperties;

public abstract class Platform {

    private final String platformName;
    private Platform(String platformName) {
        this.platformName = platformName;
    }

    public String toString() {
        return platformName;
    }

    /**
     * Get the Platform for the running environment.
     * @return this Platform
     */
    public static Platform getPlatform() {
        String osName = ToolkitProperties.getOsNameValue();
        String osArch = ToolkitProperties.getOsArchValue();
        return getPlatform(osName, osArch);
    }

    /**
     * Get the Platform for the selected environment.
     * @return this Platform
     */
    public static Platform getPlatform(String osName, String osArch) {

        osName = osName.toLowerCase();
        osArch = osArch.toLowerCase();

        if (osName.contains("windows")) {
            return new WindowsX64();
        }
        if (osName.contains("linux")) {
            if (osArch.contains("aarch64")) {
                return new LinuxAArch64();
            } else {
                return new LinuxX64();
            }
        }
        if (osName.contains("mac")) {
            if (osArch.contains("aarch64")) {
                return new MacOsAArch64();
            } else {
                return new MacOsX64();
            }
        }
        throw new Error("Unsupported Platform detected");
    }

    /**
     * Get the path to the standard (platform-specific) jipher OpenSSL location.
     * @return The path to the standard (platform-specific) jipher OpenSSL location
     */
    public abstract Path getOpensslPath();

    /**
     * Get the file name of the OpenSSL crypto library.
     * @return The file name
     */
    public abstract String getCryptoLibFilename();


    public abstract static class Unix extends Platform {

        Unix(String name) {
            super(name);
        }

        @Override
        public Path getOpensslPath() {
            return Paths.get("/opt", "jipher", "openssl");
        }

        @Override
        public String getCryptoLibFilename() {
            return "libcrypto.so.3";
        }
    }

    public abstract static class Linux extends Unix {
        Linux(String name) {
            super(name);
        }
    }

    public static class LinuxX64 extends Linux {
        LinuxX64() {
            super("linux_x64");
        }
    }
    public static class LinuxAArch64 extends Linux {
        LinuxAArch64() {
            super("linux_aarch64");
        }
    }

    public static class MacOs extends Unix {
        MacOs(String name) {
            super(name);
        }

        @Override
        public String getCryptoLibFilename() {
            return "libcrypto.3.dylib";
        }
    }

    public static class MacOsX64 extends MacOs {
        MacOsX64() {
            super("macos_x64");
        }
    }
    public static class MacOsAArch64 extends MacOs {
        MacOsAArch64() {
            super("macos_aarch64");
        }
    }

    public static class WindowsX64 extends Platform {

        WindowsX64() {
            super("windows_x64");
        }

        @Override
        public Path getOpensslPath() {
            return Paths.get("C:", "Program Files", "jipher", "openssl");
        }

        @Override
        public String getCryptoLibFilename() {
            return "libcrypto-3-x64.dll";
        }
    }

}
