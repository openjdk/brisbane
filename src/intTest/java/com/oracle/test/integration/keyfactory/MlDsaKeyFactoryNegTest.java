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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


public class MlDsaKeyFactoryNegTest {

    @Test
    public void testNulls() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-DSA");

        assertNull(kf.getKeySpec(null, PKCS8EncodedKeySpec.class));

        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-DSA"));
        PrivateKey prvK = KeyUtil.loadPrivate("ML-DSA", kptd.getPriv());

        assertNull(kf.getKeySpec(prvK, null));
    }

    @Test
    public void testIncorrectKey() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-DSA");
        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("RSA"));
        PrivateKey prvK = KeyUtil.loadPrivate("RSA", kptd.getPriv());
        assertThrows(InvalidKeySpecException.class, () -> kf.getKeySpec(prvK, PKCS8EncodedKeySpec.class));
    }

    @Test
    public void testIncorrectKeyFactory() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam("ML-DSA-44"));
        PrivateKey prvK44 = KeyUtil.loadPrivate("ML-DSA", kptd.getPriv());
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-DSA-87");
        assertThrows(InvalidKeyException.class, () -> kf.translateKey(prvK44));
    }

    @Test
    public void testTranslateNonAsymmetricKey() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-DSA");

        assertThrows(InvalidKeyException.class, () -> kf.translateKey(new SecretKeySpec(new byte[16], "AES")));
    }

    @Test
    public void testIncorrectKeySpec() throws Exception {
        assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        KeyPairTestData kptd = TestData.getFirst(KeyPairTestData.class, DataMatchers.secParam("ML-DSA-44"));
        PrivateKey prvK44 = KeyUtil.loadPrivate("ML-DSA", kptd.getPriv());
        PublicKey pubK44 = KeyUtil.loadPublic("ML-DSA", kptd.getPub());
        KeyFactory kf = ProviderUtil.getKeyFactory("ML-DSA");
        assertThrows(InvalidKeySpecException.class, () -> kf.getKeySpec(prvK44, X509EncodedKeySpec.class));
        assertThrows(InvalidKeySpecException.class, () -> kf.getKeySpec(pubK44, PKCS8EncodedKeySpec.class));
    }
}
