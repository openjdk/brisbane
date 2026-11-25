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

import static java.lang.Math.max;

public class EnvUtil {

    private static final String JAVA_SPECIFICATION_VER = System.getProperty("java.specification.version");
    private static final String JAVA_RUNTIME = System.getProperty("java.runtime.name");
    private static final String JAVA_VENDOR = System.getProperty("java.vendor");

    private static final String JIPHER_FIPS_ENFORCEMENT = System.getProperty("jipher.fips.enforcement");

    private static final int JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH = max(0, Integer.getInteger("jipher.pbkdf2.minimumPasswordLength", 8));

    /**
     * Returns the feature release of the running Java runtime.
     *
     * @return the Java feature release
     */
    public static int getJavaRuntimeMajorVersion() {
        return Runtime.version().feature();
    }

    public static boolean isOracleJdk() {
        return JAVA_VENDOR.startsWith("Oracle");
    }

    public static boolean isJdk26Plus() {
        return Runtime.version().feature() >= 26;
    }

    public enum FipsPolicy {
        NONE, FIPS, STRICT
    }

    public static FipsPolicy getPolicy() {
        if (JIPHER_FIPS_ENFORCEMENT == null) {
            return FipsPolicy.FIPS;
        }
        if (JIPHER_FIPS_ENFORCEMENT.equalsIgnoreCase("NONE")) {
            return FipsPolicy.NONE;
        }
        if (JIPHER_FIPS_ENFORCEMENT.equalsIgnoreCase("FIPS_STRICT")) {
            return FipsPolicy.STRICT;
        }
        return FipsPolicy.FIPS;
    }

    public static int getMinPbkdf2PasswordLength() {
        return JIPHER_PBKDF2_MINIMUM_PASSWORD_LENGTH;
    }
}
