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

package com.oracle.test.integration.keyfactory;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class MlKemKeyFactoryVectorTest {
    private static String globalMlKemKeyEncoding;
    private static final String PROP_NAME = "jdk.mlkem.pkcs8.encoding";
    private static List<KeyPairTestData> all;

    @BeforeAll
    public static void setUp() throws Exception {
        globalMlKemKeyEncoding = System.getProperty(PROP_NAME);
        all = TestData.get(KeyPairTestData.class, DataMatchers.alg("ML-KEM"));
    }

    private static Stream<Arguments> getMlKemTypes() {
        return Stream.of(Arguments.of("ML-KEM-1024"),
                Arguments.of("ML-KEM-768"),
                Arguments.of("ML-KEM-512"));
    }

    private static Stream<Arguments> getMlKemTypeAndEncodings() {
        return Stream.of(Arguments.of("ML-KEM-1024", "_EK"),
                Arguments.of("ML-KEM-1024", "_SEED"),
                Arguments.of("ML-KEM-1024", "_BOTH"),
                Arguments.of("ML-KEM-768", "_EK"),
                Arguments.of("ML-KEM-768", "_SEED"),
                Arguments.of("ML-KEM-768", "_BOTH"),
                Arguments.of("ML-KEM-512", "_EK"),
                Arguments.of("ML-KEM-512", "_SEED"),
                Arguments.of("ML-KEM-512", "_BOTH"));
    }

    @ParameterizedTest(name="testIngestionAndEqualityPrv{0}")
    @MethodSource("getMlKemTypes")
    public void testIngestionAndEqualityPrv(String mlKemType) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        List<KeyPairTestData> kptds = TestData.get(KeyPairTestData.class, DataMatchers.secParam(mlKemType));
        for (KeyPairTestData kptd : kptds) {
            String keyId = kptd.getKeyId();
            String[] keyIdParts = keyId.split("_");
            if (!"SEED".equals(keyIdParts[1])) {
                continue;
            }

            System.setProperty(PROP_NAME, "expandedKey");
            PrivateKey ekPrv = KeyUtil.loadPrivate(mlKemType, kptd.getPriv());
            byte[] ekDer = ekPrv.getEncoded();
            KeyPairTestData ekKP = kptds.stream().filter(k -> k.getKeyId().equals(keyIdParts[0] + "_EK")).findFirst().get();
            assertArrayEquals(ekKP.getPriv(), ekDer);

            System.setProperty(PROP_NAME, "both");
            PrivateKey bothPrv = KeyUtil.loadPrivate(mlKemType, kptd.getPriv());
            byte[] bothDer = bothPrv.getEncoded();
            KeyPairTestData bothKP = kptds.stream().filter(k -> k.getKeyId().equals(keyIdParts[0] + "_BOTH")).findFirst().get();
            assertArrayEquals(bothKP.getPriv(), bothDer);

            Map<PrivateKey,String> keyMap = new HashMap<>();
            keyMap.put(ekPrv, keyIdParts[0]);
            String fetchedKeyId = keyMap.get(bothPrv);
            assertEquals(fetchedKeyId, keyIdParts[0]);

            PrivateKey diffProvKey = new PrivateKey() {
                @Override
                public String getAlgorithm() {
                    return "ML-KEM";
                }
                @Override
                public byte[] getEncoded() {
                    return ekDer;
                }
                @Override
                public String getFormat() {
                    return "PKCS#8";
                }
            };
            // Equality is symmetric, hence class is important.
            assertFalse(ekPrv.equals(diffProvKey));
        }
    }

    @ParameterizedTest(name="testKeySpec{0}")
    @MethodSource("getMlKemTypes")
    public void testKeySpec(String mlKemType) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(mlKemType));
        PrivateKey prvK = KeyUtil.loadPrivate("ML-KEM", kptd.getPriv());
        PublicKey pubK = KeyUtil.loadPublic("ML-KEM", kptd.getPub());

        KeyFactory kf = ProviderUtil.getKeyFactory("ML-KEM");

        X509EncodedKeySpec pubKS = (X509EncodedKeySpec) kf.getKeySpec(pubK, X509EncodedKeySpec.class);
        assertArrayEquals(pubKS.getEncoded(), kptd.getPub());

        assertTrue(kf.getKeySpec(prvK, PKCS8EncodedKeySpec.class) instanceof PKCS8EncodedKeySpec);
    }

    @ParameterizedTest(name="testTranslateMatchingJipherPrivateKey{0}")
    @MethodSource("getMlKemTypes")
    public void testTranslateMatchingJipherPrivateKey(String mlKemType) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(mlKemType));
        KeyFactory kf = ProviderUtil.getKeyFactory(mlKemType);
        PrivateKey key = KeyUtil.loadPrivate("ML-KEM", kptd.getPriv());

        assertSame(key, kf.translateKey(key));
    }

    @ParameterizedTest(name="testTranslateMatchingJipherPublicKey{0}")
    @MethodSource("getMlKemTypes")
    public void testTranslateMatchingJipherPublicKey(String mlKemType) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(mlKemType));
        KeyFactory kf = ProviderUtil.getKeyFactory(mlKemType);
        PublicKey key = KeyUtil.loadPublic("ML-KEM", kptd.getPub());

        assertSame(key, kf.translateKey(key));
    }

    @ParameterizedTest(name="testTranslateExternalPrivateKey{0}{1}")
    @MethodSource("getMlKemTypeAndEncodings")
    public void testTranslateExternalPrivateKey(String mlKemType, String keyIdSuffix) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairTestData kptd = getTestData(mlKemType, keyIdSuffix);
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-KEM");
        PrivateKey expected = KeyUtil.loadPrivate("ML-KEM", kptd.getPriv());
        PrivateKey translated = (PrivateKey) kf.translateKey(new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "ML-KEM";
            }
            @Override
            public byte[] getEncoded() {
                return kptd.getPriv();
            }
            @Override
            public String getFormat() {
                return "PKCS#8";
            }
        });

        assertEquals(expected, translated);
    }

    @ParameterizedTest(name="testTranslateExternalPublicKey{0}{1}")
    @MethodSource("getMlKemTypeAndEncodings")
    public void testTranslateExternalPublicKey(String mlKemType, String keyIdSuffix) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairTestData kptd = getTestData(mlKemType, keyIdSuffix);
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-KEM");
        PublicKey expected = KeyUtil.loadPublic("ML-KEM", kptd.getPub());
        PublicKey translated = (PublicKey) kf.translateKey(new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "ML-KEM";
            }
            @Override
            public byte[] getEncoded() {
                return kptd.getPub();
            }
            @Override
            public String getFormat() {
                return "X.509";
            }
        });

        assertArrayEquals(expected.getEncoded(), translated.getEncoded());
        assertEquals(expected.getAlgorithm(), translated.getAlgorithm());
    }

    @AfterAll
    public static void resetGlobal() {
        if (globalMlKemKeyEncoding == null) {
            System.clearProperty(PROP_NAME);
        } else {
            System.setProperty(PROP_NAME, globalMlKemKeyEncoding);
        }
    }

    private static KeyPairTestData getTestData(String mlKemType, String keyIdSuffix) {
        Predicate<KeyPairTestData> matchType = kptd -> kptd.getSecParam().equals(mlKemType);
        Predicate<KeyPairTestData> matchEncoding = kptd -> kptd.getKeyId().endsWith(keyIdSuffix);
        Predicate<KeyPairTestData> match = matchType.and(matchEncoding);
        return all.stream().filter(match).findFirst().get();
    }

}
