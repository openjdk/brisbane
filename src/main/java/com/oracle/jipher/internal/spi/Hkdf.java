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

package com.oracle.jipher.internal.spi;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Abstract implementation of the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
 * <p>
 * This class implements the {@link KDFSpi} service provider interface for HKDF and
 * supports three hash algorithms - SHA-256, SHA-384 and SHA-512 - via concrete inner
 * subclasses.
 */
public abstract class Hkdf extends KDFSpi {

    /** Underlying hash algorithm for the HMAC component of HKDF. */
    private final MdAlg mdAlg;
    /** Length of the HMAC output in bytes (e.g., 32 for SHA-256). */
    private final int hmacLen;

    /**
     * Constructs an {@code Hkdf} instance for the specified hash algorithm.
     *
     * @param mdAlg          the message-digest algorithm used by the HMAC
     * @param macLen         the length of the HMAC digest in bytes
     * @param kdfParameters  must be {@code null}; HKDF does not support additional parameters
     * @throws InvalidAlgorithmParameterException if {@code kdfParameters} is not {@code null}
     */
    Hkdf(MdAlg mdAlg, int macLen, KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
        super(kdfParameters);
        if (kdfParameters != null) {
            throw new InvalidAlgorithmParameterException("HKDF- " + mdAlg.getAlg() + " does not support parameters");
        }
        this.mdAlg = mdAlg;
        this.hmacLen = macLen;
    }

    private byte[] consolidateKeyMaterial(List<SecretKey> keys) throws InvalidAlgorithmParameterException {
        if (keys == null) {
            throw new InvalidAlgorithmParameterException("List of key segments could not be consolidated");
        }

        if (keys.isEmpty()) {
            return new byte[0];
        }

        if (keys.size() == 1) {
            return (keys.get(0)).getEncoded();
        }

        // Concatenate keyMaterial
        byte[] concatenatedKeyMaterial = null;
        int length = 0;

        ArrayList<byte[]> keyMaterials = new ArrayList<>(keys.size());
        try {
            for (SecretKey key : keys) {
                byte[] keyMaterial = key.getEncoded();
                keyMaterials.add(keyMaterial);
                length += keyMaterial.length;
            }
            concatenatedKeyMaterial = new byte[length];
            ByteBuffer buffer = ByteBuffer.wrap(concatenatedKeyMaterial);
            for (byte[] keyMaterial : keyMaterials) {
                buffer.put(keyMaterial);
            }
            return concatenatedKeyMaterial;
        } catch (Exception e) {
            clearArray(concatenatedKeyMaterial);
            throw e;
        } finally {
            for (byte[] keyMaterial : keyMaterials) {
                clearArray(keyMaterial);
            }
        }
    }

    private static void checkStrength(byte[] keyMaterial) throws InvalidAlgorithmParameterException {
        try {
            Fips.enforcement().checkStrength(CryptoOp.KEYDERIVE, "KDF", keyMaterial.length * 8);
        } catch (FIPSPolicyException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
    }

    @Override
    protected KDFParameters engineGetParameters() {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // JCA ensures alg is neither null nor empty string
        byte[] derivedData = this.engineDeriveData(derivationSpec);
        try {
            return new SecretKeySpec(derivedData, alg);
        } finally {
            clearArray(derivedData);
        }
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec) throws InvalidAlgorithmParameterException {
        byte[] keyMaterial = null;
        byte[] salt = null;
        byte[] info;
        int length;

        try {
            if (derivationSpec instanceof HKDFParameterSpec.Extract extract) {
                keyMaterial = consolidateKeyMaterial(extract.ikms());
                salt = consolidateKeyMaterial(extract.salts());
                checkStrength(keyMaterial);
                return Kdf.hkdfExtract(mdAlg, keyMaterial, salt, this.hmacLen);
            } else if (derivationSpec instanceof HKDFParameterSpec.Expand expand) {
                if ((keyMaterial = expand.prk().getEncoded()) == null) {
                    throw new InvalidAlgorithmParameterException("Cannot retrieve PRK");
                }
                if ((info = expand.info()) == null) {
                    info = new byte[0];
                }
                // RFC 5869 2.3. Step 2: Expand
                // PRK      a pseudorandom key of at least HashLen octets
                if (keyMaterial.length < hmacLen) {
                    throw new InvalidAlgorithmParameterException("prk must be at least " + hmacLen + " bytes");
                }
                // L        length of output keying material in octets (<= 255*HashLen)
                length = expand.length();
                if (length > this.hmacLen * 255) {
                    throw new InvalidAlgorithmParameterException("Requested length exceeds maximum allowed length");
                }
                // FIPS enforcement check is not required as the minimum supported hmac length in bits is more than 112.
                return Kdf.hkdfExpand(mdAlg, keyMaterial, info, length);
            } else if (derivationSpec instanceof HKDFParameterSpec.ExtractThenExpand extractThenExpand) {
                keyMaterial = consolidateKeyMaterial(extractThenExpand.ikms());
                salt = consolidateKeyMaterial(extractThenExpand.salts());
                if ((info = extractThenExpand.info()) == null) {
                    info = new byte[0];
                }
                // RFC 5869 2.3. Step 2: Expand
                // L        length of output keying material in octets (<= 255*HashLen)
                length = extractThenExpand.length();
                if (length > this.hmacLen * 255) {
                    throw new InvalidAlgorithmParameterException("Requested length exceeds maximum allowed length");
                }
                checkStrength(keyMaterial);
                return Kdf.hkdfExtractThenExpand(mdAlg, keyMaterial, salt, info, length);
            } else {
                throw new InvalidAlgorithmParameterException("HKDF derivation requires a valid HKDFParameterSpec");
            }
        } finally {
            clearArray(keyMaterial);
            clearArray(salt);
        }
    }

    /** HKDF-SHA256 */
    public static class HkdfSha256 extends Hkdf {
        public HkdfSha256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super(MdAlg.SHA256, 32, kdfParameters);
        }
    }

    /** HKDF-SHA256 */
    public static class HkdfSha384 extends Hkdf {
        public HkdfSha384(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super(MdAlg.SHA384, 48, kdfParameters);
        }
    }

    /** HKDF-SHA512 */
    public static class HkdfSha512 extends Hkdf {
        public HkdfSha512(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException {
            super(MdAlg.SHA512, 64, kdfParameters);
        }
    }
}
