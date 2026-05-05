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

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertTrue;


@RunWith(Parameterized.class)
public class KeyPairDestroyTest {
    final private String alg;
    PrivateKey destroyedPrivateKey;

    @Parameterized.Parameters(name="{0}")
    public static Collection<String> params() throws Exception {
        List<String> params = new ArrayList<>();
        params.add("DH");
        params.add("EC");
        params.add("RSA");
        if (FipsProviderInfoUtil.isMlKemSupported()) {
            params.add("ML-KEM");
        }
        if (FipsProviderInfoUtil.isMlDsaSupported()) {
            params.add("ML-DSA");
        }
        return params;
    }

    public KeyPairDestroyTest(String algorithm) {
        this.alg = algorithm;
    }

    @Before
    public void createDestroyedPrivateKey() throws Exception {
        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(this.alg);
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        privateKey.destroy();

        this.destroyedPrivateKey = privateKey;
    }

    @Test
    public void destroyKeyTest() {
        assertTrue(destroyedPrivateKey.isDestroyed());
    }

    @Test(expected = IllegalStateException.class)
    public void getEncodingOfDestroyedKeyTest() {
        destroyedPrivateKey.getEncoded();
    }

    @Test(expected = IllegalStateException.class)
    public void getPrivateComponentOfDestroyedKeyTest() {
        Assume.assumeTrue(!alg.equals("ML-KEM") && !alg.equals("ML-DSA"));
        if (destroyedPrivateKey instanceof DHPrivateKey) {
            ((DHPrivateKey) destroyedPrivateKey).getX();
        } else if (destroyedPrivateKey instanceof DSAPrivateKey) {
            ((DSAPrivateKey) destroyedPrivateKey).getX();
        } else if (destroyedPrivateKey instanceof ECPrivateKey) {
            ((ECPrivateKey) destroyedPrivateKey).getS();
        } else if (destroyedPrivateKey instanceof RSAPrivateKey) {
            ((RSAPrivateKey) destroyedPrivateKey).getPrivateExponent();
        }
    }

    @Test(expected = IllegalStateException.class)
    public void getComponentsOfDestroyedRsaPrivateCrtKeyTest() {
        Assume.assumeTrue(destroyedPrivateKey instanceof RSAPrivateCrtKey);
        RSAPrivateCrtKey rsaPrivateCrrKey = (RSAPrivateCrtKey) destroyedPrivateKey;

        IllegalStateException e = null;

        try {
            rsaPrivateCrrKey.getModulus();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPublicExponent();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPrivateExponent();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPrimeP();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPrimeQ();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPrimeExponentP();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getPrimeExponentQ();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        try {
            rsaPrivateCrrKey.getCrtCoefficient();
            Assert.fail("Should have thrown an IllegalStateException");
        } catch (IllegalStateException ise) {
            e = ise;
        }

        throw e;
    }

    @Test(expected = IllegalStateException.class)
    public void getEncodeDestroyedKeyTest() {
        destroyedPrivateKey.getEncoded();
    }

    @Test(expected = IllegalStateException.class)
    public void useDestroyedKeyTest() throws Exception {
        if (destroyedPrivateKey instanceof DHPrivateKey) {
            KeyAgreement keyAgreement = ProviderUtil.getKeyAgreement(alg);
            keyAgreement.init(destroyedPrivateKey);
        } else if (destroyedPrivateKey instanceof ECPrivateKey) {
            Signature signature = ProviderUtil.getSignature("SHA256with" + alg + "DSA");
            signature.initSign(destroyedPrivateKey);
        } else if (destroyedPrivateKey instanceof RSAPrivateKey) {
            Cipher cipher = ProviderUtil.getCipher(alg + "/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, destroyedPrivateKey);
        } else {
            String algorithm = destroyedPrivateKey.getAlgorithm();
            if ("ML-KEM".equals(algorithm)) {
                KEM kem = ProviderUtil.getKEM(algorithm);
                kem.newDecapsulator(destroyedPrivateKey);
            } else if ("ML-DSA".equals(algorithm)) {
                Signature signature = ProviderUtil.getSignature(algorithm);
                signature.initSign(destroyedPrivateKey);
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void translateDestroyedKeyTest() throws Exception {
        KeyFactory keyFactory = ProviderUtil.getKeyFactory(alg);

        if (destroyedPrivateKey instanceof DHPrivateKey) {
            keyFactory.translateKey(new DummyDestroyedDHPrivateKey());
        } else if (destroyedPrivateKey instanceof DSAPrivateKey) {
            keyFactory.translateKey(new DummyDestroyedDSAPrivateKey());
        } else if (destroyedPrivateKey instanceof ECPrivateKey) {
            keyFactory.translateKey(new DummyDestroyedECPrivateKey());
        } else if (destroyedPrivateKey instanceof RSAPrivateKey) {
            keyFactory.translateKey(new DummyDestroyedRSAPrivateKey());
        } else {
            String algorithm = destroyedPrivateKey.getAlgorithm();
            if ("ML-KEM".equals(algorithm)) {
                keyFactory.translateKey(new DummyDestroyedMLKEMPrivateKey());
            } else if ("ML-DSA".equals(algorithm)) {
                keyFactory.translateKey(new DummyDestroyedMLDSAPrivateKey());
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void serializeDestroyedKeyTest() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(destroyedPrivateKey);
    }

    static class DummyDestroyedPrivateKey implements PrivateKey {
        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            throw new IllegalStateException("Destroyed Key");
        }

        @Override
        public boolean isDestroyed() {
            return true;
        }
    }

    static class DummyDestroyedDHPrivateKey extends DummyDestroyedPrivateKey implements DHPrivateKey  {
        @Override
        public BigInteger getX() {
            throw new IllegalStateException("Destroyed Key");
        }

        @Override
        public DHParameterSpec getParams() {
            throw new IllegalStateException("Destroyed Key");
        }
    }

    static class DummyDestroyedDSAPrivateKey extends DummyDestroyedPrivateKey implements DSAPrivateKey  {
        @Override
        public BigInteger getX() {
            throw new IllegalStateException("Destroyed Key");
        }

        @Override
        public DSAParams getParams() {
            throw new IllegalStateException("Destroyed Key");
        }
    }

    static class DummyDestroyedECPrivateKey extends DummyDestroyedPrivateKey implements ECPrivateKey  {
        @Override
        public String getAlgorithm() {
            return "EC";
        }

        @Override
        public BigInteger getS() {
            throw new IllegalStateException("Destroyed Key");
        }

        @Override
        public ECParameterSpec getParams() {
            throw new IllegalStateException("Destroyed Key");
        }
    }

    static class DummyDestroyedRSAPrivateKey extends DummyDestroyedPrivateKey implements RSAPrivateKey  {
        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public BigInteger getPrivateExponent() {
            throw new IllegalStateException("Destroyed Key");
        }

        @Override
        public BigInteger getModulus() {
            throw new IllegalStateException("Destroyed Key");
        }
    }

    static class DummyDestroyedMLKEMPrivateKey extends DummyDestroyedPrivateKey {

        @Override
        public String getAlgorithm() {
            return "ML-KEM";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }
    }

    static class DummyDestroyedMLDSAPrivateKey extends DummyDestroyedPrivateKey {

        @Override
        public String getAlgorithm() {
            return "ML-DSA";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }
    }
}
