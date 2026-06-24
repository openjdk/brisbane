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

package com.oracle.test.integration.kem;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


public class KemMethodTest {

    private static Stream<Arguments> getArgs() {
        return Stream.of(Arguments.of("ML-KEM-512", 768, 32),
                Arguments.of("ML-KEM-768", 1088, 32),
                Arguments.of("ML-KEM-1024", 1568, 32));
    }

    @ParameterizedTest(name="testEncapSize{0}")
    @MethodSource("getArgs")
    public void testEncapSizes(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encap = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertEquals(encapSize, encap.encapsulationSize());
        assertEquals(secretSize, encap.secretSize());
    }

    @ParameterizedTest(name="testEncapSize{0}")
    @MethodSource("getArgs")
    public void testDecapSizes(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decap = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertEquals(encapSize, decap.encapsulationSize());
        assertEquals(secretSize, decap.secretSize());
    }

    @ParameterizedTest(name="testFullLC{0}")
    @MethodSource("getArgs")
    public void testFullLC(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();
        byte[] encapsulation = encapsulated.encapsulation();
        assertEquals(encapSize, encapsulation.length);
        byte[] skEnc =  encapsulated.key().getEncoded();
        assertEquals(secretSize, skEnc.length);

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        byte[] skPeerEnc = decapsulator.decapsulate(encapsulation).getEncoded();
        assertArrayEquals(skEnc, skPeerEnc);
    }

    @ParameterizedTest(name="testEncapNullAlgorithm{0}")
    @MethodSource("getArgs")
    public void testEncapNullAlgorithm(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(NullPointerException.class, () -> encapsulator.encapsulate(0, secretSize, null));
    }

    @ParameterizedTest(name="testEncapNegFrom{0}")
    @MethodSource("getArgs")
    public void testEncapNegFrom(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(IndexOutOfBoundsException.class, () -> encapsulator.encapsulate(-1, secretSize, "Generic"));
    }

    @ParameterizedTest(name="testEncapFromGtTo{0}")
    @MethodSource("getArgs")
    public void testEncapFromGtTo(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(IndexOutOfBoundsException.class, () -> encapsulator.encapsulate(secretSize/2 + 1, secretSize/2, "Generic"));
    }

    @ParameterizedTest(name="testEncapToGtSecretSize{0}")
    @MethodSource("getArgs")
    public void testEncapToGtSecretSize(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(IndexOutOfBoundsException.class, () -> encapsulator.encapsulate(0, secretSize + 1, "Generic"));
    }

    @ParameterizedTest(name="testEncapNonZeroFrom{0}")
    @MethodSource("getArgs")
    public void testEncapNonZeroFrom(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(UnsupportedOperationException.class, () -> encapsulator.encapsulate(1, secretSize, "Generic"));
    }

    @ParameterizedTest(name="testEncapToNotEqualSecretSize{0}")
    @MethodSource("getArgs")
    public void testEncapToNotEqualSecretSize(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));
        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        assertThrows(UnsupportedOperationException.class, () -> encapsulator.encapsulate(0, secretSize - 1, "Generic"));
    }

    @ParameterizedTest(name="testDecapNullAlgorithm{0}")
    @MethodSource("getArgs")
    public void testDecapNullAlgorithm(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(NullPointerException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), 0, secretSize, null));
    }

    @ParameterizedTest(name="testDecapNegFrom{0}")
    @MethodSource("getArgs")
    public void testDecapNegFrom(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(IndexOutOfBoundsException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), -1, secretSize, "Generic"));
    }

    @ParameterizedTest(name="testDecapFromGtTo{0}")
    @MethodSource("getArgs")
    public void testDecapFromGtTo(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(IndexOutOfBoundsException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), secretSize/2 + 1, secretSize/2, "Generic"));
    }

    @ParameterizedTest(name="testDecapToGtSecretSize{0}")
    @MethodSource("getArgs")
    public void testDecapToGtSecretSize(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(IndexOutOfBoundsException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), 0, secretSize + 1, "Generic"));
    }

    @ParameterizedTest(name="testDecapNonZeroFrom{0}")
    @MethodSource("getArgs")
    public void testDecapNonZeroFrom(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(UnsupportedOperationException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), 1, secretSize, "Generic"));
    }

    @ParameterizedTest(name="testDecapToNotEqualSecretSize{0}")
    @MethodSource("getArgs")
    public void testDecapToNotEqualSecretSize(String algoName, int encapSize, int secretSize) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(algoName));

        PublicKey pubK = KeyUtil.loadPublic(algoName, kp.getPub());
        Encapsulator encapsulator = ProviderUtil.getKEM(algoName).newEncapsulator(pubK);
        Encapsulated encapsulated = encapsulator.encapsulate();

        PrivateKey prvK = KeyUtil.loadPrivate(algoName, kp.getPriv());
        Decapsulator decapsulator = ProviderUtil.getKEM(algoName).newDecapsulator(prvK);
        assertThrows(UnsupportedOperationException.class, () -> decapsulator.decapsulate(encapsulated.encapsulation(), 0, secretSize - 1, "Generic"));
    }
}
