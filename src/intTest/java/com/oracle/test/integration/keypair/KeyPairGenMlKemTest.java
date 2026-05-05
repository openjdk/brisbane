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

package com.oracle.test.integration.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.test.integration.keypair.PairwiseHelper.pairwiseConsistency;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class KeyPairGenMlKemTest {

    private static Stream<Arguments> mlKemTypes() {
        return Stream.of(
            Arguments.of("ML-KEM", "ML-KEM-768"),
            Arguments.of("ML-KEM-512", "ML-KEM-512"),
            Arguments.of("ML-KEM-768", "ML-KEM-768"),
            Arguments.of("ML-KEM-1024", "ML-KEM-1024"));
    }

    @ParameterizedTest(name="genTest{0}")
    @MethodSource("mlKemTypes")
    public void genTest(String kpgName, String defaultAlgo) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(kpgName);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey prvK = kp.getPrivate();
        PublicKey pubK = kp.getPublic();
        AlgorithmParameterSpec prvParams = prvK.getParams();
        AlgorithmParameterSpec pubParams = pubK.getParams();

        assertTrue(prvParams instanceof NamedParameterSpec);
        assertTrue(pubParams instanceof NamedParameterSpec);

        assertEquals(defaultAlgo, ((NamedParameterSpec)prvParams).getName());
        assertEquals(defaultAlgo, ((NamedParameterSpec)pubParams).getName());

        pairwiseConsistency(pubK, prvK);
    }

    @ParameterizedTest(name="testFixedSeed{0}")
    @MethodSource("mlKemTypes")
    public void testFixedSeed(String kpgName, String defaultAlgo) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        SecureRandom sr = new FixedSizeRand(64);

        KeyPairGenerator jipherKPG = ProviderUtil.getKeyPairGenerator(kpgName);
        jipherKPG.initialize(new NamedParameterSpec(defaultAlgo), sr);
        KeyPair jipherKP = jipherKPG.generateKeyPair();
        PrivateKey jipherPrv = jipherKP.getPrivate();

        jipherKPG.initialize(new NamedParameterSpec(defaultAlgo), sr);
        KeyPair jipherKP2 = jipherKPG.generateKeyPair();
        PrivateKey jipherPrv2 = jipherKP2.getPrivate();

        assertNotEquals(jipherPrv, jipherPrv2);
        assertEquals(jipherPrv.getAlgorithm(), jipherPrv2.getAlgorithm());
        assertEquals(jipherPrv.getFormat(), jipherPrv2.getFormat());
    }

    @ParameterizedTest(name="testInitializeParams{0}-{1}")
    @MethodSource("mlKemTypes")
    public void testInitializeParams(String kpgName, String expectedAlgo) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(kpgName);
        kpg.initialize(new NamedParameterSpec(expectedAlgo));

        assertGeneratedKeyParams(kpg, expectedAlgo);
    }

    @ParameterizedTest(name="testInitializeNullParams{0}")
    @MethodSource("mlKemTypes")
    public void testInitializeNullParams(String kpgName, String defaultAlgo) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(kpgName);
        kpg.initialize((AlgorithmParameterSpec) null);

        assertGeneratedKeyParams(kpg, defaultAlgo);
    }

    @ParameterizedTest(name="testInitializeParamsAndRandom{0}-{1}")
    @MethodSource("mlKemTypes")
    public void testInitializeParamsAndRandom(String kpgName, String expectedAlgo) throws Exception {
        Assumptions.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());

        SecureRandom sr = new FixedSizeRand(64);
        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(kpgName);
        kpg.initialize(new NamedParameterSpec(expectedAlgo), sr);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey prvK = kp.getPrivate();

        kpg.initialize(new NamedParameterSpec(expectedAlgo), sr);
        KeyPair kp2 = kpg.generateKeyPair();
        PrivateKey prvK2 = kp2.getPrivate();

        assertKeyParams(prvK.getParams(), expectedAlgo);
        assertKeyParams(kp.getPublic().getParams(), expectedAlgo);
        assertNotEquals(prvK, prvK2);
        assertEquals(prvK.getAlgorithm(), prvK2.getAlgorithm());
        assertEquals(prvK.getFormat(), prvK2.getFormat());
    }

    private static void assertGeneratedKeyParams(KeyPairGenerator kpg, String expectedAlgo) throws Exception {
        KeyPair kp = kpg.generateKeyPair();

        assertKeyParams(kp.getPrivate().getParams(), expectedAlgo);
        assertKeyParams(kp.getPublic().getParams(), expectedAlgo);
        pairwiseConsistency(kp.getPublic(), kp.getPrivate());
    }

    private static void assertKeyParams(AlgorithmParameterSpec params, String expectedAlgo) {
        assertTrue(params instanceof NamedParameterSpec);
        assertEquals(expectedAlgo, ((NamedParameterSpec)params).getName());
    }
}
