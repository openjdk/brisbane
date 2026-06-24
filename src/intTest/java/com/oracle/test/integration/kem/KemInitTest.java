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


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KEM;

import org.junit.jupiter.api.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


public class KemInitTest {

    @Test
    public void testNullPrivateKeyDecap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        assertThrows(InvalidKeyException.class, () -> kem.newDecapsulator(null));
    }

    @Test
    public void testMismatchedPrivateKeyVariantDecap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class,DataMatchers.secParam("ML-KEM-512"));
        PrivateKey prvK = KeyUtil.loadPrivate("ML-KEM-512", kp.getPriv());
        KEM kem = ProviderUtil.getKEM("ML-KEM-1024");
        assertThrows(InvalidKeyException.class, () -> kem.newDecapsulator(prvK));
    }

    @Test
    public void testNonNullAlgParamsDecap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM"));
        PrivateKey prvK = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        assertThrows(InvalidAlgorithmParameterException.class, () -> kem.newDecapsulator(prvK, new NamedParameterSpec(kp.getSecParam())));
    }

    @Test
    public void testNullPrivateKeyEncap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        assertThrows(InvalidKeyException.class, () -> kem.newEncapsulator(null));
    }

    @Test
    public void testMismatchedPublicKeyVariantEncap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam("ML-KEM-512"));
        PublicKey pubK = KeyUtil.loadPublic("ML-KEM-512", kp.getPub());
        KEM kem = ProviderUtil.getKEM("ML-KEM-1024");
        assertThrows(InvalidKeyException.class, () -> kem.newEncapsulator(pubK));
    }

    @Test
    public void testNonNullAlgParamsEncap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM"));
        PublicKey pubK = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> kem.newEncapsulator(pubK, new NamedParameterSpec(kp.getSecParam()), null));
    }

    @Test
    public void testTranslateKeyDecap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM"));
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        kem.newDecapsulator(new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "";
            }

            @Override
            public String getFormat() {
                return "";
            }

            @Override
            public byte[] getEncoded() {
                return kp.getPriv();
            }
        });
    }

    @Test
    public void testTranslateKeyEncap() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM"));
        KEM kem = ProviderUtil.getKEM("ML-KEM");
        kem.newEncapsulator(new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "";
            }

            @Override
            public String getFormat() {
                return "";
            }

            @Override
            public byte[] getEncoded() {
                return kp.getPub();
            }
        });
    }
}
