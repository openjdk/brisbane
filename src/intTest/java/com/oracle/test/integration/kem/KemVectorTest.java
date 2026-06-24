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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KemEncapsulatedTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


public class KemVectorTest {

    private static Stream<Arguments> fetchEncapsulations() throws Exception {
        List<KemEncapsulatedTestVector> allKems = TestData.get(KemEncapsulatedTestVector.class, null);
        return allKems.stream().map((kem) -> Arguments.of(kem.getDescription(), kem));
    }
    @ParameterizedTest(name="decapsulate{0}}")
    @MethodSource("fetchEncapsulations")
    public void decapsulate(String alg, KemEncapsulatedTestVector kemTv) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(kemTv.getKeyId()));
        PrivateKey prvK = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
        KEM kem = ProviderUtil.getKEM(alg);
        Decapsulator decap = kem.newDecapsulator(prvK);
        SecretKey sk = decap.decapsulate(kemTv.getEncapsulated());
        assertArrayEquals(sk.getEncoded(), kemTv.getData());
    }

    @ParameterizedTest(name="decapsulateWithVariant{0}}")
    @MethodSource("fetchEncapsulations")
    public void decapsulateWithVariant(String alg, KemEncapsulatedTestVector kemTv) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        Set<String> suffixes = Stream.of("BOTH", "SEED", "EK").collect(Collectors.toSet());
        String originalKeyId = kemTv.getKeyId();
        String[] keyIdParts = originalKeyId.split("_");
        suffixes.remove(keyIdParts[1]);
        for (String variantSuffix : suffixes) {
            String keyIdVariant = keyIdParts[0] + "_" + variantSuffix;
            KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(keyIdVariant));
            PrivateKey prvK = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            KEM kem = ProviderUtil.getKEM(alg);
            Decapsulator decap = kem.newDecapsulator(prvK);
            SecretKey sk = decap.decapsulate(kemTv.getEncapsulated());
            assertArrayEquals(sk.getEncoded(), kemTv.getData());
        }
    }

    @ParameterizedTest(name="decapsulateWrongKey{0}}")
    @MethodSource("fetchEncapsulations")
    public void decapsulateWrongKey(String alg, KemEncapsulatedTestVector kemTv) throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        Set<String> allSecParams = Stream.of("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").collect(Collectors.toSet());
        allSecParams.remove(alg);
        for (String wrongSecParam : allSecParams) {
            KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam(wrongSecParam));
            PrivateKey prvK = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            KEM kem = ProviderUtil.getKEM(wrongSecParam);
            Decapsulator decap = kem.newDecapsulator(prvK);
            assertThrows(DecapsulateException.class, () -> decap.decapsulate(kemTv.getEncapsulated()));
        }
    }
}
