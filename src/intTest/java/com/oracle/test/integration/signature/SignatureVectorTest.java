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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.SignatureTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.AlgorithmUtil;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.keyId;


@RunWith(Parameterized.class)
public class SignatureVectorTest {

    @Parameters(name = "{0}:{index}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(SignatureTestVector.class);
    }

    private final String alg;
    private final PublicKey pub;
    private final PrivateKey priv;
    private final byte[] data;
    private final byte[] sig;
    private AlgorithmParameterSpec spec;

    public SignatureVectorTest(String description, SignatureTestVector tv) throws Exception {
        this.alg = tv.getAlg();

        Assume.assumeTrue(FipsProviderInfoUtil.isSHA1DigestSignatureSupported() || !(this.alg.toUpperCase().contains("SHA1") || this.alg.toUpperCase().contains("SHA-1")));
        Assume.assumeTrue((FipsProviderInfoUtil.isDSASupported() && EnvUtil.getPolicy() != EnvUtil.FipsPolicy.STRICT) || !this.alg.endsWith("withDSA"));
        Assume.assumeTrue(FipsProviderInfoUtil.isMlDsaSupported() || !this.alg.contains("ML-DSA"));

        if (tv.getKeyId() != null) {
            KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
            this.pub = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
            if (this.alg.endsWith("withDSA")) {
                // JipherJCE does not support DSA private keys.
                this.priv = null;
            } else {
                this.priv = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            }

            if (tv.getParams() != null) {
                String digestName = tv.getParams().digest() == null ?
                        AlgorithmUtil.digestFromDigestSignature(this.alg) : tv.getParams().digest();
                String digestStandardName = AlgorithmUtil.Algorithm.byName(digestName).getStandardName();
                Assume.assumeTrue(FipsProviderInfoUtil.isSHA1DigestSignatureSupported() || !digestStandardName.equals("SHA-1"));

                int saltLen = tv.getParams().getSaltLen();
                int digestLength = digestStandardName.equalsIgnoreCase("SHA-1") ? 20 :
                        Integer.parseInt(digestStandardName.substring(digestStandardName.length() - 3)) / 8;
                Assume.assumeTrue(
                        "RSA PSS Signature verification disallows a salt length larger than the message digest size",
                        saltLen <= digestLength);

                this.spec = new PSSParameterSpec(digestName, "MGF1", new MGF1ParameterSpec(digestName),
                        tv.getParams().getSaltLen(), PSSParameterSpec.TRAILER_FIELD_BC);
            }
        } else {
            throw new Error();
        }
        this.data = tv.getData();
        this.sig = tv.getSignature();
    }

    void skipIfSha1NotAllowed() {
        Assume.assumeFalse("SHA1 signatures not allowed for current FIPS policy", this.alg.startsWith("SHA1") && EnvUtil.getPolicy() != EnvUtil.FipsPolicy.NONE);
        if (this.spec != null) {
            Assume.assumeFalse("SHA1 signatures not allowed for current FIPS policy", ((PSSParameterSpec) this.spec).getDigestAlgorithm().equalsIgnoreCase("SHA-1")
                    && EnvUtil.getPolicy() != EnvUtil.FipsPolicy.NONE);
        }
    }

    @Test
    public void testSignVerify() throws Exception {
        Assume.assumeFalse("DSA not allowed for signature generation", this.alg.endsWith("withDSA"));
        skipIfSha1NotAllowed();
        Signature signer = ProviderUtil.getSignature(alg);
        signer.initSign(this.priv, null);
        if (this.spec != null) {
            signer.setParameter(this.spec);
        }
        signer.update(this.data);
        byte[] signed = signer.sign();

        doVerify(signed);
    }

    @Test
    public void testVerify() throws Exception {
        doVerify(this.sig);
    }

    void doVerify(byte[] sigBytes) throws Exception {
        Signature ver = ProviderUtil.getSignature(alg);
        ver.initVerify(this.pub);
        if (this.spec != null) {
            ver.setParameter(this.spec);
        }
        ver.update(this.data, 0, this.data.length);
        Assert.assertTrue(ver.verify(sigBytes, 0, sigBytes.length));
    }
}
