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

package com.oracle.jipher.internal.openssl;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jipher.internal.common.MlUtil;
import com.oracle.jipher.internal.common.MlUtil.PrivateKeyData;
import com.oracle.jipher.internal.common.MlUtil.PublicKeyData;
import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;


public class PkeyTest {
    OpenSsl openSsl;
    OSSL_LIB_CTX libCtx;
    OsslArena testArena;

    private DHPrivateKeySpec dhPrivateKeySpec;
    private DHPublicKeySpec dhPublicKeySpec;
    private ECPrivateKeySpec ecPrivateKeySpec;
    private ECPublicKeySpec ecPublicKeySpec;
    private RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec;
    private PKCS8EncodedKeySpec mlKEMPrivateKeySpec;
    private X509EncodedKeySpec mlKEMPublicKeySpec;
    private PKCS8EncodedKeySpec mlDSAPrivateKeySpec;
    private X509EncodedKeySpec mlDSAPublicKeySpec;

    @Before
    public void setUp() throws Exception {
        KeyPairTestData keyPairTestData;

        openSsl = OpenSsl.getInstance();
        libCtx = LibCtx.getInstance();
        testArena = OsslArena.ofConfined();

        keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("DH").secParam(Integer.toString(2048)));
        this.dhPrivateKeySpec = (DHPrivateKeySpec) KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.dhPublicKeySpec = (DHPublicKeySpec) KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());

        keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("EC").secParam("secp256r1"));
        this.ecPrivateKeySpec = (ECPrivateKeySpec) KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.ecPublicKeySpec = (ECPublicKeySpec) KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());

        keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("RSA").secParam(Integer.toString(2048)));
        this.rsaPrivateCrtKeySpec = (RSAPrivateCrtKeySpec) KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());

        keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM").secParam("ML-KEM-768"));
        // Cannot use KeyUtil.getPrivateKeySpec or KeyUtil.getPublicKeySpec here because:
        // 1. There is no breakdown of the key components.
        // 2. JDK 25 KeyFactory does not support all encoding formats.
        this.mlKEMPrivateKeySpec = new PKCS8EncodedKeySpec(keyPairTestData.getPriv());
        this.mlKEMPublicKeySpec = new X509EncodedKeySpec(keyPairTestData.getPub());

        keyPairTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-DSA").secParam("ML-DSA-65"));
        this.mlDSAPrivateKeySpec = new PKCS8EncodedKeySpec(keyPairTestData.getPriv());
        this.mlDSAPublicKeySpec = new X509EncodedKeySpec(keyPairTestData.getPub());
    }

    @Test
    public void newMLKEMPriv() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMLKEMSupported());
        PrivateKeyData prvData = MlUtil.decodePrivateKey(mlKEMPrivateKeySpec.getEncoded());
        Assert.assertEquals("Unexpected Alg OID", prvData.algOid(), "2.16.840.1.101.3.4.4.2");
        try (Pkey pkey = Pkey.newMLPriv("ML-KEM-768", prvData.seed(), prvData.expandedKey())) {
            Map<String, byte[]> pkeyparams = pkey.getMLPrivKeyData(true);
            if (prvData.seed() != null) {
                Assert.assertArrayEquals(prvData.seed(), pkeyparams.get(EVP_PKEY.PKEY_PARAM_ML_SEED));
            }
            if (prvData.expandedKey() != null) {
                Assert.assertArrayEquals(prvData.expandedKey(), pkeyparams.get(EVP_PKEY.PKEY_PARAM_PRIV_KEY));
            }
        }
    }

    @Test
    public void newMLKEMPub() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMLKEMSupported());
        PublicKeyData pubData = MlUtil.decodePublicKey(mlKEMPublicKeySpec.getEncoded());
        Assert.assertEquals("Unexpected Alg OID", pubData.algOid(), "2.16.840.1.101.3.4.4.2");
        try (Pkey pkey = Pkey.newMLPub("ML-KEM-768", pubData.pubKeyPayload())) {
            Assert.assertArrayEquals(pkey.getMLPubKeyData(), pubData.pubKeyPayload());
        }
    }

    @Test
    public void newMLDSAPriv() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMLDSASupported());
        PrivateKeyData prvData = MlUtil.decodePrivateKey(mlDSAPrivateKeySpec.getEncoded());
        Assert.assertEquals("Unexpected Alg OID", prvData.algOid(), "2.16.840.1.101.3.4.3.18");
        try (Pkey pkey = Pkey.newMLPriv("ML-DSA-65", prvData.seed(), prvData.expandedKey())) {
            Map<String, byte[]> pkeyparams = pkey.getMLPrivKeyData(true);
            if (prvData.seed() != null) {
                Assert.assertArrayEquals(prvData.seed(), pkeyparams.get(EVP_PKEY.PKEY_PARAM_ML_SEED));
            }
            if (prvData.expandedKey() != null) {
                Assert.assertArrayEquals(prvData.expandedKey(), pkeyparams.get(EVP_PKEY.PKEY_PARAM_PRIV_KEY));
            }
        }
    }

    @Test
    public void newMLDSAPub() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMLDSASupported());
        PublicKeyData pubData = MlUtil.decodePublicKey(mlDSAPublicKeySpec.getEncoded());
        Assert.assertEquals("Unexpected Alg OID", pubData.algOid(), "2.16.840.1.101.3.4.3.18");
        try (Pkey pkey = Pkey.newMLPub("ML-DSA-65", pubData.pubKeyPayload())) {
            Assert.assertArrayEquals(pkey.getMLPubKeyData(), pubData.pubKeyPayload());
        }
    }

    @Test
    public void newDhParams() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        try (Pkey pkey = Pkey.newDhParams(dhParamSpec)) {
            Assert.assertArrayEquals(pkey.getDhParams().getP().toByteArray(), dhParamSpec.getP().toByteArray());
            Assert.assertArrayEquals(pkey.getDhParams().getG().toByteArray(), dhParamSpec.getG().toByteArray());
        }
    }

    @Test
    public void newDhPriv() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        BigInteger x = dhPrivateKeySpec.getX();
        try (Pkey pkey = Pkey.newDhPriv(dhParamSpec, x)) {
            Assert.assertArrayEquals(pkey.getDhPrivateKeyAsBigInteger().toByteArray(), x.toByteArray());
            Assert.assertArrayEquals(pkey.getDhPrivateKeyAsByteArray(), x.toByteArray());
        }
        try (Pkey pkey = Pkey.newDhPriv(dhParamSpec, x.toByteArray())) {
            Assert.assertArrayEquals(pkey.getDhPrivateKeyAsBigInteger().toByteArray(), x.toByteArray());
            Assert.assertArrayEquals(pkey.getDhPrivateKeyAsByteArray(), x.toByteArray());
        }
    }

    @Test
    public void newDhPub() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPublicKeySpec.getP(), dhPublicKeySpec.getG());
        BigInteger y = dhPublicKeySpec.getY();
        try (Pkey pkey = Pkey.newDhPub(dhParamSpec, y)) {
            Assert.assertArrayEquals(pkey.getDhPublicKey().toByteArray(), y.toByteArray());
        }
    }


    @Test
    public void newEcParams() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            Assert.assertEquals(pkey.getEcCurve(), curve);
        }
    }

    @Test
    public void newEcPriv() throws Exception {
        BigInteger priv = ecPrivateKeySpec.getS();
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcPriv(curve, priv)) {
            Assert.assertArrayEquals(pkey.getEcPrivateKeyAsByteArray(), priv.toByteArray());
            Assert.assertArrayEquals(pkey.getEcPrivateKeyAsBigInteger().toByteArray(), priv.toByteArray());
        }
        try (Pkey pkey = Pkey.newEcPriv(curve, priv.toByteArray())) {
            Assert.assertArrayEquals(pkey.getEcPrivateKeyAsByteArray(), priv.toByteArray());
            Assert.assertArrayEquals(pkey.getEcPrivateKeyAsBigInteger().toByteArray(), priv.toByteArray());
        }
    }

    @Test
    public void newEcPub() throws Exception {
        ECPoint point = ecPublicKeySpec.getW();
        EcCurve curve = NamedCurves.lookup(ecPublicKeySpec.getParams());
        ECParameterSpec params = ecPublicKeySpec.getParams();

        try (Pkey pkey = Pkey.newEcPub(curve, point, params)) {
            Assert.assertArrayEquals(pkey.getEcPublicKey().getAffineX().toByteArray(), point.getAffineX().toByteArray());
            Assert.assertArrayEquals(pkey.getEcPublicKey().getAffineY().toByteArray(), point.getAffineY().toByteArray());
        }
    }

    @Test
    public void newRsaPriv() throws Exception {
        try (Pkey pkey = Pkey.newRsaPriv(rsaPrivateCrtKeySpec)) {
            Assert.assertArrayEquals(pkey.getRsaModulus().toByteArray(), rsaPrivateCrtKeySpec.getModulus().toByteArray());
        }
        try (Pkey pkey = Pkey.newRsaPriv(
                rsaPrivateCrtKeySpec.getModulus().toByteArray(),
                rsaPrivateCrtKeySpec.getPublicExponent().toByteArray(),
                rsaPrivateCrtKeySpec.getPrivateExponent().toByteArray(),
                rsaPrivateCrtKeySpec.getPrimeP().toByteArray(),
                rsaPrivateCrtKeySpec.getPrimeQ().toByteArray(),
                rsaPrivateCrtKeySpec.getPrimeExponentP().toByteArray(),
                rsaPrivateCrtKeySpec.getPrimeExponentQ().toByteArray(),
                rsaPrivateCrtKeySpec.getCrtCoefficient().toByteArray())) {
            Assert.assertArrayEquals(pkey.getRsaModulus().toByteArray(), rsaPrivateCrtKeySpec.getModulus().toByteArray());
        }
    }

    @Test
    public void newRsaPub() throws Exception {
        BigInteger n = rsaPrivateCrtKeySpec.getModulus();
        BigInteger e = rsaPrivateCrtKeySpec.getPublicExponent();

        try (Pkey pkey = Pkey.newRsaPub(n, e)) {
            Assert.assertArrayEquals(pkey.getRsaModulus().toByteArray(), n.toByteArray());
            Assert.assertArrayEquals(pkey.getRsaPublicExponent().toByteArray(), e.toByteArray());
        }
    }

    /* Negative Tests */

    @Test (expected = IllegalStateException.class)
    public void getDHParamsWrongKeyTypeNeg() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            pkey.getDhParams();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getDhPrivateKeyWrongKeyTypeNeg() throws Exception {
        BigInteger priv = ecPrivateKeySpec.getS();
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcPriv(curve, priv)) {
            pkey.getDhPrivateKeyAsBigInteger();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getDhPrivateKeyWrongContentTypeNeg() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPublicKeySpec.getP(), dhPublicKeySpec.getG());
        BigInteger y = dhPublicKeySpec.getY();
        try (Pkey pkey = Pkey.newDhPub(dhParamSpec, y)) {
            pkey.getDhPrivateKeyAsBigInteger();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getDhPublicKeyWrongKeyTypeNeg() throws Exception {
        BigInteger priv = ecPrivateKeySpec.getS();
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcPriv(curve, priv)) {
            pkey.getDhPublicKey();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getDhPublicKeyWrongContentTypeNeg() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        try (Pkey pkey = Pkey.newDhParams(dhParamSpec)) {
            pkey.getDhPublicKey();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getEcCurveWrongKeyTypeNeg() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        BigInteger x = dhPrivateKeySpec.getX();
        try (Pkey pkey = Pkey.newDhPriv(dhParamSpec, x)) {
            pkey.getEcCurve();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getEcPrivateKeyWrongKeyTypeNeg() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            pkey.getEcPrivateKeyAsBigInteger();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getEcPrivateKeyWrongContentTypeNeg() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        BigInteger x = dhPrivateKeySpec.getX();
        try (Pkey pkey = Pkey.newDhPriv(dhParamSpec, x)) {
            pkey.getEcPrivateKeyAsBigInteger();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getEcPublicKeyWrongKeyTypeNeg() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported());
        DHParameterSpec dhParamSpec  = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
        BigInteger x = dhPrivateKeySpec.getX();
        try (Pkey pkey = Pkey.newDhPriv(dhParamSpec, x)) {
            pkey.getEcPublicKey();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getEcPublicKeyWrongContentTypeNeg() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            pkey.getEcPublicKey();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getRsaParamWrongKeyTypeNeg() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            pkey.getRsaModulus();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getRsaParamWrongContentType() throws Exception {
        BigInteger n = rsaPrivateCrtKeySpec.getModulus();
        BigInteger e = rsaPrivateCrtKeySpec.getPublicExponent();
        try (Pkey pkey = Pkey.newRsaPub(n, e)) {
            pkey.getRsaCrtCoefficient();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getRsaPrivateKeyDataWrongKeyTypeNeg() throws Exception {
        EcCurve curve = NamedCurves.lookup(ecPrivateKeySpec.getParams());
        try (Pkey pkey = Pkey.newEcParams(curve)) {
            pkey.getRsaPrivateKeyData();
        }
    }

    @Test (expected = IllegalStateException.class)
    public void getRsaPrivateKeyDataWrongContentTypeNeg() throws Exception {
        BigInteger n = rsaPrivateCrtKeySpec.getModulus();
        BigInteger e = rsaPrivateCrtKeySpec.getPublicExponent();
        try (Pkey pkey = Pkey.newRsaPub(n, e)) {
            pkey.getRsaPrivateKeyData();
        }
    }
}
