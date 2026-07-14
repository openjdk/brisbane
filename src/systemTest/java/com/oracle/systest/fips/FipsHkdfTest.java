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

package com.oracle.systest.fips;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.systest.SysTestUtil.isFipsException;
import static com.oracle.systest.fips.OperationResult.FIPS_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.OTHER_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.SUCCESS;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class FipsHkdfTest {
    static final String ALGORITHM = "HKDF-SHA256";
    static final int MIN_SECURITY_STRENGTH = 112; // bit

    // Enforcement of KDF minimum security strength was first added to OpenSSL in version 3.4.0
    static final boolean OPENSSL_ENFORCES_MIN_SECURITY_STRENGTH =
            (FipsProviderInfoUtil.getMajorVersion() > 3) ||
            (FipsProviderInfoUtil.getMajorVersion() == 3 && FipsProviderInfoUtil.getMinorVersion() >= 4) ||
            (FipsProviderInfoUtil.getMajorVersion() == 1 && FipsProviderInfoUtil.getMinorVersion() == 2);

    private final AlgorithmParameterSpec spec;
    private final OperationResult expected;

    public FipsHkdfTest(EnvUtil.FipsPolicy policy, String paramLabel, AlgorithmParameterSpec spec, OperationResult expected) {
        this.spec = spec;
        this.expected = expected;
    }

    @Parameterized.Parameters(name="policy={0}:{1}:expect={3}")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> p = new ArrayList<>();
        EnvUtil.FipsPolicy policy = EnvUtil.getPolicy();
        p.add(new Object[]{policy, "acceptable extract only parameters", HKDFParameterSpec.ofExtract()
                .addIKM(new byte[MIN_SECURITY_STRENGTH / 8]).addSalt(new byte[0])
                .extractOnly(), SUCCESS});
        p.add(new Object[]{policy, "short ikm extract only", HKDFParameterSpec.ofExtract()
                .addIKM(new byte[MIN_SECURITY_STRENGTH / 8 - 1]).addSalt(new byte[0])
                .extractOnly(), policy == EnvUtil.FipsPolicy.NONE ?
                (OPENSSL_ENFORCES_MIN_SECURITY_STRENGTH ? OTHER_EXCEPTION : SUCCESS) : FIPS_EXCEPTION});
        p.add(new Object[]{policy, "acceptable extract then expand parameters", HKDFParameterSpec.ofExtract()
                .addIKM(new byte[MIN_SECURITY_STRENGTH / 8]).addSalt(new byte[0])
                .thenExpand(new byte[0], 32), SUCCESS});
        p.add(new Object[]{policy, "short ikm extract then expand parameters", HKDFParameterSpec.ofExtract()
                .addIKM(new byte[MIN_SECURITY_STRENGTH / 8 - 1]).addSalt(new byte[0])
                .thenExpand(new byte[0], 32), policy == EnvUtil.FipsPolicy.NONE ?
                (OPENSSL_ENFORCES_MIN_SECURITY_STRENGTH ? OTHER_EXCEPTION : SUCCESS) : FIPS_EXCEPTION});
        return p;
    }

    @Test
    public void deriveData() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALGORITHM);
        // Disable delayed provider selection
        Assert.assertEquals("JipherJCE", kdf.getProviderName());
        try {
            kdf.deriveData(this.spec);
            assertEquals(this.expected, SUCCESS);
        } catch (InvalidAlgorithmParameterException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
        }
    }

    @Test
    public void deriveKey() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALGORITHM);
        // Disable delayed provider selection
        Assert.assertEquals("JipherJCE", kdf.getProviderName());
        try {
            kdf.deriveKey("generic", this.spec);
            assertEquals(this.expected, SUCCESS);
        } catch (InvalidAlgorithmParameterException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
        }
    }
}
