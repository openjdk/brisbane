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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.keyfactory.EcParamTestUtil;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KeyPairGenNegativeTest {

    static DHParameterSpec SPEC_2048 =  new DHParameterSpec(
            new BigInteger(1, TestUtil.hexToBytes(
                    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"+
                            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
                            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"+
                            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"+
                            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"+
                            "886B423861285C97FFFFFFFFFFFFFFFF")),
            BigInteger.valueOf(2));

    KeyPairGenerator kpRsa;
    KeyPairGenerator kpEc;
    KeyPairGenerator kpDh;
    KeyPairGenerator kpMlKem;
    KeyPairGenerator kpMlDsa;

    @Before
    public void setUp() throws Exception {
        kpRsa = ProviderUtil.getKeyPairGenerator("RSA");
        kpEc = ProviderUtil.getKeyPairGenerator("EC");
        kpDh = ProviderUtil.getKeyPairGenerator("DH");
        if (FipsProviderInfoUtil.isMlKemSupported()) {
            kpMlKem = ProviderUtil.getKeyPairGenerator("ML-KEM");
        }
        if (FipsProviderInfoUtil.isMlDsaSupported()) {
            kpMlDsa = ProviderUtil.getKeyPairGenerator("ML-DSA");
        }
    }

    @Test(expected = InvalidParameterException.class)
    public void initRsaBitsTooSmall() throws Exception {
        kpRsa.initialize(5);
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidParameterException.class)
    public void initRsaBits0() throws Exception {
        kpRsa.initialize(0);
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaSpecBits0() throws Exception {
        kpRsa.initialize(new RSAKeyGenParameterSpec(0, RSAKeyGenParameterSpec.F4));
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaPubExpNegative() throws Exception {
        kpRsa.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4.negate()));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaPubExpEven() throws Exception {
        kpRsa.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4.add(BigInteger.ONE)));
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaPubExpOddBelowPermittedRange() throws Exception { // Odd value outside range 2^16 < e < 2^256
        kpRsa.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(2).pow(16).subtract(BigInteger.ONE)));
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaPubExpOddAbovePermittedRange() throws Exception { // Odd value outside range 2^16 < e < 2^256
        kpRsa.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(2).pow(256).add(BigInteger.ONE)));
        kpRsa.generateKeyPair();
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initRsaBadSpec() throws Exception {
        kpRsa.initialize(new ECGenParameterSpec("lalala"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void generateRsaWithLargeModulusAndLargePublicExponent() throws Exception {
        int SMALL_MODULUS_BITS = 3072;  // OPENSSL_RSA_SMALL_MODULUS_BITS
        int MAX_RESTRICTED_EXPLEN = 64; // OPENSSL_RSA_MAX_PUBEXP_BITS

        int keySize = SMALL_MODULUS_BITS + 1;
        BigInteger publicExponent = BigInteger.ZERO.setBit(MAX_RESTRICTED_EXPLEN);
        RSAKeyGenParameterSpec keySpec = new RSAKeyGenParameterSpec(keySize, publicExponent);

        kpRsa.initialize(keySpec);
    }

    @Test(expected = InvalidParameterException.class)
    public void initEcBitsNotSupported1() throws Exception {
        kpEc.initialize(255);
    }

    @Test(expected = InvalidParameterException.class)
    public void initEcBitsNotSupported2() throws Exception {
        kpEc.initialize(1000);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initEcGenParameterSpecCurveUnknown() throws Exception {
        kpEc.initialize(new ECGenParameterSpec("secp112r1"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initEcBadParameterSpec() throws Exception {
        kpEc.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initEcNullSpec() throws Exception {
        kpEc.initialize(null);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initEcCustomCurve() throws Exception {
        kpEc.initialize(EcParamTestUtil.getUnsupported());
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initDhNullSpec() throws Exception {
        kpDh.initialize(null);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initDhBadSpec() throws Exception {
        kpDh.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test(expected = InvalidParameterException.class)
    public void initDhUnsuppSpec() throws Exception {
        BigInteger p = BigInteger.probablePrime(512, ThreadLocalRandom.current());
        BigInteger g = BigInteger.valueOf(2);
        kpDh.initialize(new DHParameterSpec(p, g));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initDhNullComponentSpec() throws Exception {
        kpDh.initialize(new DHParameterSpec(null, BigInteger.valueOf(2)));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initDhNegativeComponentSpec() throws Exception {
        BigInteger p = SPEC_2048.getP().negate();
        BigInteger g = SPEC_2048.getG();
        kpDh.initialize(new DHParameterSpec(p, g));
    }

    @Test(expected = InvalidParameterException.class)
    public void initDhKeySizeUnsupported() throws Exception {
        kpDh.initialize(8080);
    }

    @Test
    public void initInvalidDHParams() throws Exception {
        BigInteger p = new BigInteger(1, TestUtil.hexToBytes("00F82CD0B121DF91E2F9D1A84A9A89402A40B9544184E1FDBD27B045D122D719BF1CB7188330EA0E866D3DD2E779C81146316D7280DA9E09FFEA58F4219484B8E7C606F8C6C15F5BD87C21730CC83484495EF991980DCE1D704C6FFB7330B691CCEE948F39935BDF4A1E6CEDAAA6EF37C83868EA0FFA529537384E3595D14F50FF044F9BA38CED5AB1B291D29C8DD2DA43C711E662666FE0C241835E2100C08210FBF0E180F7941CD12C8D98BE70CD68FCC7F57D40EB447D68BA269F6A36E6672D232B59077AD48933C95924E81C524775C7EB5E4D2996C21D7714DA89CF76C91C6E48E3678B80C75CE90437B3C8608886BB9595876C200CA77E554E6E0F724B39"));
        BigInteger g = new BigInteger(1, TestUtil.hexToBytes("25895D1722207B2E06032D0269587DFDA581800D5510A5605888A7E9868BCFE625CFB6CFF9641AE18BDF0595CC3A7668F014D7E9A818006F7A6E63B1919A25E41389249F0880A968CB5E63714CA3B7CACFFB1C27BE121F7E4122FB711FCEA26F7FE2645799A9AF6007D00F846B04242A1A9664F084BD06762C66BF2BB1E42CFDF5CAE58BD4796272150A304115ACF499FACF41F57225CA6EEDFCB909F0331B9719E5B80F18399A677D0574BED3FDEA92BD05524B0FBCED902B73A203E26A864C99994B19B7C93959E58D5623480349B4468B47975C0F8676F05A429DFE31D7FB9A100F73C8B17C151391C63E814F93F7F249B7E861C7958DF56D021063DEA150"));

        doInitInvalid(kpDh, new DHParameterSpec(null, g), "null");

        doInitInvalid(kpDh, new DHParameterSpec(BigInteger.ZERO, g), "zero");

        doInitInvalid(kpDh, new DHParameterSpec(p, null), "null");
        doInitInvalid(kpDh, new DHParameterSpec(p, BigInteger.ZERO), "zero");
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidMlKemParams() throws InvalidAlgorithmParameterException {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        kpMlKem.initialize(new NamedParameterSpec("ML-DSA-44"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidMlDsaParams() throws InvalidAlgorithmParameterException {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        kpMlDsa.initialize(new NamedParameterSpec("ML-KEM-1024"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidMlKemSpecificParams() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        ProviderUtil.getKeyPairGenerator("ML-KEM-512").initialize(new NamedParameterSpec("ML-KEM-768"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidMlDsaSpecificParams() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        ProviderUtil.getKeyPairGenerator("ML-DSA-44").initialize(new NamedParameterSpec("ML-DSA-65"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initMlKemNonNamedParameterSpec() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        kpMlKem.initialize(new IvParameterSpec(new byte[3]));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initMlDsaNonNamedParameterSpec() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        kpMlDsa.initialize(new IvParameterSpec(new byte[3]));
    }

    @Test
    public void initInvalidMlKemKeySize() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlKemSupported());
        for (String algorithm : new String[] {"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            try {
                ProviderUtil.getKeyPairGenerator(algorithm).initialize(1024);
                fail("Expected exception");
            } catch (InvalidParameterException e) {
                // Expected exception
            }
        }
    }

    @Test
    public void initInvalidMlDsaKeySize() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isMlDsaSupported());
        for (String algorithm : new String[] {"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
            try {
                ProviderUtil.getKeyPairGenerator(algorithm).initialize(87);
                fail("Expected exception");
            } catch (InvalidParameterException e) {
                // Expected exception
            }
        }
    }

    private void doInitInvalid(KeyPairGenerator kpg, AlgorithmParameterSpec spec, String msgCheck) throws Exception {
        try {
            kpg.initialize(spec);
            fail("Expected exception");
        } catch (InvalidAlgorithmParameterException e) {
            if (msgCheck != null) {
                assertTrue(e.getMessage().contains(msgCheck));
            }
        }
    }
}
