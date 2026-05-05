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

package com.oracle.jipher.internal.spi;

import java.security.spec.NamedParameterSpec;

public class PQCParameterSpecs {

    public static final String STR_ML_KEM_512 = "ML-KEM-512";
    public static final String STR_ML_KEM_768 = "ML-KEM-768";
    public static final String STR_ML_KEM_1024 = "ML-KEM-1024";
    public static final NamedParameterSpec ML_KEM_512 = new NamedParameterSpec(STR_ML_KEM_512);
    public static final NamedParameterSpec ML_KEM_768 = new NamedParameterSpec(STR_ML_KEM_768);
    public static final NamedParameterSpec ML_KEM_1024 = new NamedParameterSpec(STR_ML_KEM_1024);

    public static final String STR_ML_DSA_44 = "ML-DSA-44";
    public static final String STR_ML_DSA_65 = "ML-DSA-65";
    public static final String STR_ML_DSA_87 = "ML-DSA-87";
    public static final NamedParameterSpec ML_DSA_44 = new NamedParameterSpec(STR_ML_DSA_44);
    public static final NamedParameterSpec ML_DSA_65 = new NamedParameterSpec(STR_ML_DSA_65);
    public static final NamedParameterSpec ML_DSA_87 = new NamedParameterSpec(STR_ML_DSA_87);

    static boolean isMLKEMSpec(NamedParameterSpec spec) {
        assert spec != null;
        String specName = spec.getName();
        return switch (specName) {
            case STR_ML_KEM_512, STR_ML_KEM_768, STR_ML_KEM_1024 -> true;
            default -> false;
        };
    }
    static boolean isMLDSASpec(NamedParameterSpec spec) {
        assert spec != null;
        String specName = spec.getName();
        return switch (specName) {
            case STR_ML_DSA_44, STR_ML_DSA_65, STR_ML_DSA_87 -> true;
            default -> false;
        };
    }
}
