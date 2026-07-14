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

package com.oracle.test.integration.signature;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.DataSize;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.SignatureTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.AlgorithmUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static com.oracle.jiphertest.testdata.DataMatchers.pssMatcher;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Signature algorithm test cases.
 */
public abstract class SignatureTest {

    String alg;
    byte[] testData;
    PrivateKey privKey;
    PublicKey pubKey;
    AlgorithmParameterSpec spec;

    SignatureTestVector tv;
    KeyPairTestData kp;

    Signature sig;

    // Whether to call setParameters before init (used by PSS).
    private final boolean setParamsFirst;

    SignatureTest(String alg) {
        this(alg, false);
    }

    SignatureTest(String alg, boolean setParamsFirst) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported() || !alg.contains("withDSA"));
        this.alg = alg;
        this.setParamsFirst = setParamsFirst;
    }

    void verify(KeyPairTestData keyPair, AlgorithmParameterSpec params, byte[] data, byte[] signature) throws Exception {
        Signature verifier = ProviderUtil.getSignature(this.alg);
        verifier.initVerify(KeyUtil.loadPublic(keyPair.getAlg(), keyPair.getPub()));
        if (params != null) {
            verifier.setParameter(params);
        }
        verifier.update(data);
        assertTrue(verifier.verify(signature, 0, signature.length));
    }

    void verify(byte[] data, byte[] signature) throws Exception {
        verify(this.kp, this.spec, data, signature);
    }

    private boolean isPssAlg() {
        return this.alg.contains("MGF") || this.alg.contains("PSS");
    }

    @Before
    public void setUp() throws Exception {
        if (this.alg.equals("RSASSA-PSS")) {
            tv = TestData.getFirst(SignatureTestVector.class, pssMatcher().alg(this.alg).digest("SHA-256").dataSize(DataSize.BASIC));
        } else {
            tv = TestData.getFirst(SignatureTestVector.class, alg(this.alg).dataSize(DataSize.BASIC));
        }
        kp = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        if (this.alg.endsWith("withDSA")) {
            // Jipher does not support DSA private keys
            privKey = null;
        } else {
            privKey = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
        }
        pubKey = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
        testData = tv.getData();
        sig = ProviderUtil.getSignature(this.alg);

        if (tv.getParams() != null) {
            String digestName = tv.getParams().digest() == null ?
                    AlgorithmUtil.digestFromDigestSignature(this.alg) : tv.getParams().digest();
            this.spec = new PSSParameterSpec(digestName, "MGF1", new MGF1ParameterSpec(digestName),
                    tv.getParams().getSaltLen(), PSSParameterSpec.TRAILER_FIELD_BC);
        }
    }

    @Test
    public void signVerify() throws Exception {
        initSign();
        sig.update(testData);
        byte[] sigBytes = sig.sign();

        verify(testData, sigBytes);
    }

    @Test
    public void signOtherProviderKey() throws Exception {
        initSign(KeyUtil.getDummyPrivateKey(kp.getAlg(), kp.getPriv()), this.spec);
        sig.update(testData);
        byte[] sigBytes = sig.sign();

        verify(testData, sigBytes);
    }

    @Test
    public void signUpdateParts() throws Exception {
        initSign();
        byte[] b1 = Arrays.copyOfRange(testData, 0, 14);
        byte[] b2 = Arrays.copyOfRange(testData, 14, testData.length);
        sig.update(b1);
        sig.update(b2);
        byte[] sigBytes = sig.sign();
        verify(testData, sigBytes);
    }

    @Test
    public void signUpdateOffLen() throws Exception {
        initSign();
        byte[] bb = new byte[testData.length + 10];
        System.arraycopy(testData, 0, bb, 7, testData.length);
        sig.update(bb, 7, testData.length);
        byte[] sigBytes = sig.sign();
        verify(testData, sigBytes);
    }

    @Test
    public void signUpdateByte() throws Exception {
        initSign();
        for (byte b: testData) {
            sig.update(b);
        }
        byte[] sigBytes = sig.sign();
        verify(testData, sigBytes);
    }

    @Test
    public void signUpdateByteBufferIndirect() throws Exception {
        initSign();
        ByteBuffer bb = ByteBuffer.wrap(testData);
        sig.update(bb);
        byte[] sigBytes = sig.sign();
        verify(testData, sigBytes);
    }

    @Test
    public void signUpdateByteBufferDirect() throws Exception {
        initSign();
        ByteBuffer bb = TestUtil.directByteBuffer(testData);
        sig.update(bb);
        byte[] sigBytes = sig.sign();
        verify(testData, sigBytes);
    }

    @Test
    public void signReuseWithoutInit() throws Exception {
        initSign();
        sig.update(testData);
        sig.sign();

        // Reuse - update();
        sig.update(testData);
        verify(testData, sig.sign());
    }

    // Tests that once init has been called the signature object
    // is independent of the key passed to init
    // (which may be destroyed by the application)
    @Test
    public void initSignDestroyKeyUpdateSign() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        PrivateKey key = KeyUtil.duplicate(this.privKey);
        initSign(key, this.spec);
        key.destroy();
        sig.update(testData);
        verify(testData, sig.sign());
    }

    // Tests that an implicit (re)init following a key destroy works
    @Test
    public void initSignUpdateSignDestroyKeyUpdateSign() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        PrivateKey key = KeyUtil.duplicate(this.privKey);
        initSign(key, this.spec);
        sig.update(testData);
        verify(testData, sig.sign());

        key.destroy();
        sig.update(testData);
        verify(testData, sig.sign());
    }

    @Test
    public void verify() throws Exception {
        initVerify();
        sig.update(testData, 0, testData.length);
        assertTrue(sig.verify(tv.getSignature()));
    }
    @Test
    public void verifyOtherProviderKey() throws Exception {
        initVerify(KeyUtil.getDummyPublicKey(kp.getAlg(), kp.getPub()), this.spec);
        sig.update(testData, 0, testData.length);
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyUpdateParts() throws Exception {
        initVerify();
        sig.update(testData, 0, 7);
        sig.update(testData, 7, testData.length - 7);
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyUpdateByte() throws Exception {
        initVerify();
        for (byte b : testData) {
            sig.update(b);
        }
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyUpdateByteBufferIndirect() throws Exception {
        initVerify();
        sig.update(ByteBuffer.wrap(testData));
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyUpdateByteBufferDirect() throws Exception {
        initVerify();
        sig.update(TestUtil.directByteBuffer(testData));
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyOffsetLen() throws Exception {
        initVerify();
        sig.update(testData);
        byte[] s = new byte[tv.getSignature().length + 100];
        System.arraycopy(tv.getSignature(), 0, s, 99, tv.getSignature().length);
        assertTrue(sig.verify(s, 99, tv.getSignature().length));
    }

    @Test
    public void verifyReuseWithoutInit() throws Exception {
        initVerify();
        sig.update(testData);
        sig.verify(tv.getSignature());

        sig.update(testData);
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void verifyReuseAfterFailure() throws Exception {
        initVerify();
        // Intentionally trigger a signature verify failure - Fails to verify outcome or throws SignatureException
        try {
            Assume.assumeFalse(sig.verify(tv.getSignature()));
        } catch (SignatureException e) {
            // Expected - for RSA digest signatures - Ignore.
        }
        // Persist with a second signature verification attempt, this time providing the correct data to verify.
        sig.update(testData);
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test
    public void signVerifyUsingSameObject() throws Exception {
        initSign();
        sig.update(testData);
        sig.sign();

        initVerify();
        sig.update(testData);
        assertTrue(sig.verify(tv.getSignature()));
    }

    @Test (expected = SignatureException.class)
    public void verifyExceptionSigEncInvalid() throws Exception {
        Assume.assumeTrue(this.alg.toUpperCase().contains("DSA"));
        initVerify();
        sig.update(testData);
        byte[] sig2 = Arrays.copyOf(tv.getSignature(), tv.getSignature().length);
        // Corrupt the SEQUENCE preamble of the DER encoding of the signature
        sig2[0]++;
        sig.verify(sig2, 0, sig2.length);
    }

    @Test
    public void verifyFailSigChanged() throws Exception {
        initVerify();
        sig.update(testData);
        byte[] sig2 = Arrays.copyOf(tv.getSignature(), tv.getSignature().length);
        if (this.alg.toUpperCase().contains("RSA")) {
            // Any tampering with the signature will almost certainly invalidate the padding (on decrypt)
            // So the test should expect a Signature exception be thrown.
            sig2[0]++; // Tamper with signature
            try {
                assertFalse(sig.verify(sig2, 0, sig2.length));
                fail("Expected SignatureException");
            } catch (SignatureException e) {
                Assume.assumeTrue(e.getCause().getMessage().contains("invalid padding"));
            }
        } else {
            Assume.assumeTrue(this.alg.toUpperCase().contains("DSA"));
            // Change the signature (being careful not to corrupt the DER encoding of the signature)
            // ECDSA-Sig-Value ::= SEQUENCE {
            // r INTEGER,
            // s INTEGER
            // }
            // SEQUENCE (0x30), Total Length, Integer(0x2) r, r Length, Possible sign byte, r ...
            sig2[5]++;
            sig2[tv.getSignature().length - 1]--;
            assertFalse(sig.verify(sig2, 0, sig2.length));
        }
    }

    @Test (expected = SignatureException.class)
    public void verifyExceptionSigTooShort() throws Exception {
        initVerify();
        sig.update(testData);
        sig.verify(tv.getSignature(), 0, tv.getSignature().length -1);
    }

    void initVerify() throws Exception {
        initVerify(this.pubKey, this.spec);
    }

    void initVerify(PublicKey pub, AlgorithmParameterSpec params) throws Exception {
        if (params != null && this.setParamsFirst) {
            sig.setParameter(params);
        }
        sig.initVerify(pub);
        if (params != null && !this.setParamsFirst) {
            sig.setParameter(params);
        }
    }

    void initSign() throws Exception {
        initSign(this.privKey, this.spec);
    }

    void initSign(PrivateKey priv, AlgorithmParameterSpec params) throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        if (params != null && this.setParamsFirst) {
            sig.setParameter(params);
        }
        sig.initSign(priv);
        if (params != null && !this.setParamsFirst) {
            sig.setParameter(params);
        }
    }

    @Test (expected = SignatureException.class)
    public void verifyExceptionSigTooLong() throws Exception {
        initVerify();
        sig.update(testData);
        byte[] bb = new byte[tv.getSignature().length + 1];
        System.arraycopy(tv.getSignature(), 0, bb, 0, tv.getSignature().length);
        sig.verify(bb);
    }

    @Test (expected = SignatureException.class)
    public void verifyExceptionSigZeroLength() throws Exception {
        initVerify();
        sig.update(testData);
        sig.verify(tv.getSignature(), 0, 0);
    }

    @Test
    public void setParameter() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        sig.initSign(privKey);
        if (!isPssAlg()) {
            try {
                sig.setParameter(null);
                fail("Expected UnsupportedOperationException for setParameter");
            } catch (UnsupportedOperationException e) {
                // expected
            }
        } else {
            sig.initSign(privKey);
            sig.setParameter(spec);
        }
    }

    @SuppressWarnings("deprecation")
    @Test(expected = UnsupportedOperationException.class)
    public void getParameterString() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        sig.initSign(privKey);
        sig.getParameter(null);
    }

    @SuppressWarnings("deprecation")
    @Test(expected = UnsupportedOperationException.class)
    public void setParameterString() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        sig.initSign(privKey);
        sig.setParameter(null, null);
    }

    @Test
    public void getParameters() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        if (!isPssAlg()) {
            try {
                sig.initSign(privKey);
                sig.getParameters();
                fail("Expected UnsupportedOperationException for getParameters");
            } catch (UnsupportedOperationException e) {
                // expected
            }
        } else {
            if (this.setParamsFirst) {
                sig.setParameter(spec);
            }
            sig.initSign(privKey);
            if (!this.setParamsFirst) {
                sig.setParameter(spec);
            }
            AlgorithmParameters params = sig.getParameters();
            assertNotNull(params);
            PSSParameterSpec pSpec = params.getParameterSpec(PSSParameterSpec.class);
            assertNotNull(pSpec);
            PSSParameterSpec thisSpec = (PSSParameterSpec) this.spec;
            assertEquals(thisSpec.getDigestAlgorithm(), pSpec.getDigestAlgorithm());
            assertEquals(thisSpec.getMGFAlgorithm(), pSpec.getMGFAlgorithm());
            assertEquals(((MGF1ParameterSpec) thisSpec.getMGFParameters()).getDigestAlgorithm(), ((MGF1ParameterSpec) pSpec.getMGFParameters()).getDigestAlgorithm());
            assertEquals(thisSpec.getSaltLength(), pSpec.getSaltLength());
            assertEquals(thisSpec.getTrailerField(), pSpec.getTrailerField());
        }
    }

    @Test(expected = InvalidKeyException.class)
    public void initVerifyWrongKey() throws Exception {
        // Private key DER instead of private
        sig.initVerify(KeyUtil.getDummyPublicKey(kp.getAlg(), kp.getPriv()));
    }

    @Test(expected = InvalidKeyException.class)
    public void initSignWrongKey() throws Exception {
        Assume.assumeFalse(this.alg.endsWith("withDSA"));
        // Public key DER instead of private
        sig.initSign(KeyUtil.getDummyPrivateKey(kp.getAlg(), kp.getPub()));
    }

    /** This case is caught by Signature class (doesn't reach provider code)
     *  but we include it for completion.
     */
    @Test(expected = SignatureException.class)
    public void updateWithoutInit() throws Exception {
        sig.update(new byte[32]);
    }
    /** This case is caught by Signature class (doesn't reach provider code)
     *  but we include it for completion.
     */
    @Test(expected = SignatureException.class)
    public void signWithoutInit() throws Exception {
        sig.sign();
    }
    /** This case is caught by Signature class (doesn't reach provider code)
     *  but we include it for completion.
     */
    @Test(expected = SignatureException.class)
    public void verifyWithoutInit() throws Exception {
        sig.verify(new byte[32]);
    }

    /**
     * Subclass which includes tests for empty data signatures (no data to update).
     */
    @RunWith(Parameterized.class)
    public static class WithDigest extends SignatureTest {

        public WithDigest(String label, String sigAlg, boolean setParamsFirst) {
            super(sigAlg, setParamsFirst);
        }
        private SignatureTestVector tvEmpty;
        private KeyPairTestData kpEmpty;
        private PSSParameterSpec specEmpty;

        @Parameterized.Parameters(name = "{0}")
        public static Collection<Object[]> algs() {
            return Arrays.asList(
                    new Object[]{"RSA", "SHA256withRSA", false},
                    new Object[]{"ECDSA", "SHA256withECDSA", false},
                    new Object[]{"DSA", "SHA256withDSA", false},
                    new Object[]{"RSASSA-PSS", "RSASSA-PSS", false},
                    new Object[]{"RSASSA-PSS(setParamsFirst)", "RSASSA-PSS", true}
                    );
        }

        @Before
        public void setUp() throws Exception {
            if (this.alg.equals("RSASSA-PSS")) {
                tvEmpty = TestData.getFirst(SignatureTestVector.class, pssMatcher().alg(this.alg).digest("SHA-256").dataSize(DataSize.EMPTY));
            } else {
                tvEmpty = TestData.getFirst(SignatureTestVector.class, alg(this.alg).dataSize(DataSize.EMPTY));
            }
            kpEmpty = TestData.getFirst(KeyPairTestData.class, keyId(tvEmpty.getKeyId()));
            super.setUp();

            if (tvEmpty.getParams() != null) {
                String digestAlg = tvEmpty.getParams().digest() == null ?
                        AlgorithmUtil.digestFromDigestSignature(this.alg) : tvEmpty.getParams().digest();
                MGF1ParameterSpec mgf = new MGF1ParameterSpec(digestAlg);
                this.specEmpty = new PSSParameterSpec(digestAlg, "MGF1", mgf, tvEmpty.getParams().getSaltLen(), 1);
            }
        }

        @Test
        public void verifyEmpty() throws Exception {
            PublicKey publicKey = KeyUtil.loadPublic(kpEmpty.getAlg(), kpEmpty.getPub());
            initVerify(publicKey, specEmpty);
            assertTrue(sig.verify(tvEmpty.getSignature()));

            initVerify(publicKey, specEmpty);
            sig.update(new byte[0]);
            assertTrue(sig.verify(tvEmpty.getSignature()));

            initVerify(publicKey, specEmpty);
            sig.update(new byte[10], 0, 0);
            assertTrue(sig.verify(tvEmpty.getSignature()));
        }

        @Test
        public void signEmptyVerify() throws Exception {
            Assume.assumeFalse(this.alg.endsWith("withDSA"));
            PrivateKey privKey = KeyUtil.loadPrivate(kpEmpty.getAlg(), kpEmpty.getPriv());
            initSign(privKey, specEmpty);
            byte[] signature = sig.sign();
            verify(kpEmpty, specEmpty, new byte[0], signature);

            sig = ProviderUtil.getSignature(this.alg);
            initSign(privKey, specEmpty);
            sig.update(new byte[0]);
            verify(kpEmpty, specEmpty, new byte[0], sig.sign());

            initSign(privKey, specEmpty);
            sig.update(new byte[12], 0, 0);
            verify(kpEmpty, specEmpty, new byte[0], sig.sign());
        }

        @Test
        public void signEmptyByteBuffer() throws Exception {
            Assume.assumeFalse(this.alg.endsWith("withDSA"));
            initSign(KeyUtil.loadPrivate(kpEmpty.getAlg(), kpEmpty.getPriv()), specEmpty);
            sig.update(ByteBuffer.wrap(new byte[0]));
            byte[] signature = sig.sign();
            verify(kpEmpty, specEmpty, new byte[0], signature);
        }

        @Test
        public void signReuseWithoutInitUpdate() throws Exception {
            Assume.assumeFalse(this.alg.endsWith("withDSA"));
            initSign(KeyUtil.loadPrivate(kpEmpty.getAlg(), kpEmpty.getPriv()), specEmpty);
            sig.sign();

            // Reuse - sign();
            verify(kpEmpty, specEmpty, new byte[0], sig.sign());
        }
    }

    /**
     * Subclass for signatures that don't do digesting.
     */
    @RunWith(Parameterized.class)
    public static class NoDigest extends SignatureTest {
        public NoDigest(String label, String sigAlg) {
            super(sigAlg);
        }

        @Parameterized.Parameters(name = "{0}")
        public static Collection<Object[]> algs() {
            return Arrays.asList(
                    new Object[]{"RSA", "NONEwithRSA"},
                    new Object[]{"ECDSA", "NONEwithECDSA"},
                    new Object[]{"DSA", "NONEwithDSA"});
        }

        @Test(expected = SignatureException.class)
        public void signEmptySignature() throws Exception {
            Assume.assumeFalse(this.alg.endsWith("withDSA"));
            sig.initSign(privKey);
            sig.sign();
        }

        @Test(expected = SignatureException.class)
        public void signEmptyUpdateSignature() throws Exception {
            Assume.assumeFalse(this.alg.endsWith("withDSA"));
            sig.initSign(privKey);
            sig.update(new byte[0]);
            sig.sign();
        }
    }

    /**
     * Additional test cases for RSA PSS with explicit digest.
     */
    public static class RSAPSSWithDigest {

        PrivateKey privKey;
        PublicKey pubKey;
        PSSParameterSpec spec;
        SignatureTestVector tv;
        KeyPairTestData kp;

        Signature sig;

        @Before
        public void setUp() throws Exception {
            String alg = "SHA256withRSAandMGF1";
            tv = TestData.getFirst(SignatureTestVector.class, pssMatcher().alg("RSASSA-PSS").digest("SHA-256").dataSize(DataSize.BASIC));
            kp = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
            privKey = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            pubKey = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
            this.spec = new PSSParameterSpec("SHA-256", "MGF1",
                    new MGF1ParameterSpec("SHA-256"), tv.getParams().getSaltLen(), 1);
            sig = ProviderUtil.getSignature(alg);
        }

        @Test
        public void setParameter() throws Exception {
            sig.initVerify(pubKey);
            sig.setParameter(spec);
            sig.update(tv.getData());
            assertTrue(sig.verify(tv.getSignature()));
        }

        @Test
        public void verifyWithoutParameters() throws Exception {
            sig.initVerify(pubKey);
            sig.update(tv.getData());
            assertTrue(sig.verify(tv.getSignature()));
        }


        @Test(expected = SignatureException.class)
        public void verifyWithWrongSaltLen() throws Exception {
            sig.initVerify(pubKey);
            sig.setParameter(
                    new PSSParameterSpec(spec.getDigestAlgorithm(), "MGF1",
                            spec.getMGFParameters(), this.tv.getParams().getSaltLen() + 1, 1));
            sig.update(tv.getData());
            assertFalse(sig.verify(tv.getSignature()));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalid() throws Exception {
            sig.initVerify(pubKey);
            sig.setParameter(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(17)));
        }

        @Test(expected = IllegalStateException.class)
        public void setParametersBeforeInit() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 42, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidDigest() throws Exception {
            sig.initSign(privKey);
            sig.setParameter(
                    new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGF() throws Exception {
            sig.initSign(privKey);
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGFSpec() throws Exception {
            sig.initSign(privKey);
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 23, 1), 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGFSpecDigest() throws Exception {
            sig.initSign(privKey);
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384, 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidTF() throws Exception {
            sig.initSign(privKey);
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2));
        }

    }

    /**
     * Additional test cases for RSASSA-PSS.
     */
    public static class RSASSAPSS {

        PrivateKey privKey;
        PublicKey pubKey;
        PSSParameterSpec spec;
        SignatureTestVector tv;
        KeyPairTestData kp;

        Signature sig;

        @Before
        public void setUp() throws Exception {
            String alg = "RSASSA-PSS";
            tv = TestData.getFirst(SignatureTestVector.class, pssMatcher().alg(alg).digest("SHA-256").dataSize(DataSize.BASIC));
            kp = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
            privKey = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            pubKey = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
            this.spec = new PSSParameterSpec(tv.getParams().digest(), "MGF1",
                    new MGF1ParameterSpec(tv.getParams().digest()), tv.getParams().getSaltLen(), 1);
            sig = ProviderUtil.getSignature(alg);
        }

        @Test(expected = ProviderException.class)
        public void setParamsAfterUpdate() throws Exception {
            sig.initVerify(pubKey);
            sig.setParameter(spec);
            sig.update(tv.getData());
            sig.setParameter(spec);
        }

        @Test(expected = SignatureException.class)
        public void updateVerifyWithoutParameters() throws Exception {
            sig.initVerify(pubKey);
            sig.update(new byte[32]);
        }

        @Test(expected = SignatureException.class)
        public void updateSignWithoutParameters() throws Exception {
            sig.initSign(privKey);
            sig.update(new byte[32]);
        }

        @Test(expected = SignatureException.class)
        public void signFinalWithoutParameters() throws Exception {
            sig.initSign(privKey);
            sig.sign();
        }

        @Test(expected = SignatureException.class)
        public void verifyFinalWithoutParameters() throws Exception {
            sig.initVerify(pubKey);
            sig.verify(tv.getSignature());
        }

        @Test(expected = SignatureException.class)
        public void verifyWithWrongSaltLen() throws Exception {
            PSSParameterSpec spec = new PSSParameterSpec(tv.getParams().digest(), "MGF1",
                    new MGF1ParameterSpec(tv.getParams().digest()), this.tv.getParams().getSaltLen() + 1, 1);
            sig.setParameter(spec);
            sig.initVerify(pubKey);
            sig.update(tv.getData());
            assertFalse(sig.verify(tv.getSignature()));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalid() throws Exception {
            sig.setParameter(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(17)));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidDigest() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-224", "MGF1",
                    new MGF1ParameterSpec("SHA-256"), 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGF() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-384", "MGF2",
                    new MGF1ParameterSpec("SHA-384"), 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGFSpec() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                    new PSSParameterSpec("SHA-256", "MGF2",
                            MGF1ParameterSpec.SHA256, 23, 1),
                    32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidMGFSpecDigest() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA384, 32, 1));
        }

        @Test(expected = InvalidAlgorithmParameterException.class)
        public void setParametersInvalidTF() throws Exception {
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                    new MGF1ParameterSpec("SHA-256"), 32, 2));
        }

    }

}
