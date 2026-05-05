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

package com.oracle.jiphertest.testdata;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;

/**
 * This class provides access to test vectors used by integration tests.
 */
public class TestData {

    static Gson gson = new Gson();
    static KeyPairs keyPairs;
    static Params params;

    static Map<Class, String> defaultMap;
    static {
        defaultMap = new HashMap<>();
        defaultMap.put(PbMacTestVector[].class, "pbmac.json");
        defaultMap.put(MacTestVector[].class, "mac.json");
        defaultMap.put(HkdfTestVector[].class, "hkdf.json");
        defaultMap.put(PbkdfTestVector[].class, "pbkdf.json");
        defaultMap.put(TlsKeyMaterialTestVector[].class, "tlskeymat.json");
        defaultMap.put(DigestTestVector[].class, "md.json");
        defaultMap.put(SymCipherTestVector[].class, "symciph.json");
        defaultMap.put(PbeCipherTestVector[].class, "pbeciph.json");
        defaultMap.put(AsymCipherTestVector[].class, "asymciph.json");
        defaultMap.put(KeyPairTestData[].class, "keypairs.json");
        defaultMap.put(ParameterTestData[].class, "parameters.json");
        defaultMap.put(SignatureTestVector[].class, "sig.json");
        defaultMap.put(KeyAgreeTestVector[].class, "keyagree.json");
        defaultMap.put(WrapCipherTestVector[].class, "wrapciph.json");
        defaultMap.put(KemEncapsulatedTestVector[].class, "kem.json");

        keyPairs = loadKeyPairs();
        params = loadParamData();
    }

    public static <T> T[] loadJson(String filename, Class<T[]> testVectorArrayClass) throws Exception {
        return gson.fromJson(getResourceAsReader(filename), testVectorArrayClass);
    }

    public static <T> T[] loadJson(Class<T[]> testVectorArrayClass) throws Exception {
        return loadJson(defaultMap.get(testVectorArrayClass), testVectorArrayClass);
    }

    @SuppressWarnings("unchecked")
    public static <T> Collection<Object[]> forParameterized(Class<T> testVectorArrayClass) throws Exception {
        T[] tvs = loadJson((Class<T[]>)(Array.newInstance(testVectorArrayClass, 0).getClass()));
        List<Object[]> data = new ArrayList<>();
        for (T t : tvs) {
            data.add(new Object[]{((TestDataItem) t).getDescription(), t});
        }
        return data;
    }

    @SuppressWarnings("unchecked")
    public static <T> List<T> get(Class<T> testVectorClass, TestDataMatcher matcher) throws Exception {
        T[] tvs = loadJson((Class<T[]>)(Array.newInstance(testVectorClass, 0).getClass()));
        List<T> items = new ArrayList<>();
        for (T tv : tvs) {
            TestDataItem item = (TestDataItem) tv;
            if (matcher == null || matcher.matches(item)) {
                items.add(tv);
            }
        }
        return items;
    }

    public static <T> T getFirst(Class<T> testVectorClass, TestDataMatcher matcher) throws Exception {
        List<T> items = get(testVectorClass, matcher);
        if (items.isEmpty()) {
            throw new Error("No test vectors were found for criteria: " + matcher);
        }
        return items.get(0);
    }

    public static InputStream getResourceAsStream(String filename) throws Exception {
        return TestData.class.getResourceAsStream(filename);
    }

    public static Reader getResourceAsReader(String filename) throws Exception {
        return new InputStreamReader(getResourceAsStream(filename));
    }

    private static KeyPairs loadKeyPairs(String filename) {
        try {
            KeyPairTestData[] kps = loadJson(filename, KeyPairTestData[].class);
            return new KeyPairs(Arrays.asList(kps));
        } catch (Exception e) {
            throw new Error("Error loading keypairs.json", e);
        }
    }

    private static KeyPairs loadKeyPairs() {
        try {
            KeyPairTestData[] kps = loadJson(KeyPairTestData[].class);
            return new KeyPairs(Arrays.asList(kps));
        } catch (Exception e) {
            throw new Error("Error loading keypairs.json", e);
        }
    }

    private static Params loadParamData() {
        try {
            ParameterTestData[] kps = loadJson(ParameterTestData[].class);
            return new Params(Arrays.asList(kps));
        } catch (Exception e) {
            throw new Error("Error loading parameters.json", e);
        }
    }

    public static KeyPairs loadKeyPairs(Reader r) {
        try {
            KeyPairTestData[] kps = gson.fromJson(r, KeyPairTestData[].class);
            return new KeyPairs(Arrays.asList(kps));
        } catch (Exception e) {
            throw new Error("Error loading keypairs.json", e);
        }
    }

    public static Params loadParamData(Reader r) {
        try {
            ParameterTestData[] kps = gson.fromJson(r, ParameterTestData[].class);
            return new Params(Arrays.asList(kps));
        } catch (Exception e) {
            throw new Error("Error loading parameters.json", e);
        }
    }
}
