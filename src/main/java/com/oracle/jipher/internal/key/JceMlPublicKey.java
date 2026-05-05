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

package com.oracle.jipher.internal.key;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newBitString;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;


public abstract sealed class JceMlPublicKey extends JceOsslPublicKey implements JceMlKey
        permits JceMlPublicKey.JceMlKemPublicKey, JceMlPublicKey.JceMlDsaPublicKey {

    protected final String mlAlgoName;

    JceMlPublicKey(String mlAlgoFamilyName, String mlAlgoName, Pkey pkey) {
        this(mlAlgoFamilyName, mlAlgoName, pkey, null);
    }

    JceMlPublicKey(String mlAlgoFamilyName, String mlAlgoName, Pkey pkey, byte[] encoding) {
        super(mlAlgoFamilyName, pkey, encoding);
        this.mlAlgoName = mlAlgoName;
    }

    @Override
    byte[] derEncode() throws InvalidKeyException {
        byte[] encodedKey = pkey.getMLPubKeyData();
        return newSequence(
                newSequence(getAlgId(variant())),
                newBitString(encodedKey)).encodeDerOctets();
    }

    @Override
    public String variant() {
        return this.mlAlgoName;
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        return new NamedParameterSpec(variant());
    }

    public static final class JceMlKemPublicKey extends JceMlPublicKey {

        public JceMlKemPublicKey(String mlKemAlgo, Pkey pkey) {
            super(ML_KEM_ALGO_FAMILY_NAME, mlKemAlgo, pkey);
        }

        public JceMlKemPublicKey(String mlKemAlgo, Pkey pkey, byte[] encoding) {
            super(ML_KEM_ALGO_FAMILY_NAME, mlKemAlgo, pkey, encoding);
        }

        @Override
        public String getAlgorithm() {
            return ML_KEM_ALGO_FAMILY_NAME;
        }
    }

    public static final class JceMlDsaPublicKey extends JceMlPublicKey {

        public JceMlDsaPublicKey(String mlDsaAlgo, Pkey pkey) {
            super(ML_DSA_ALGO_FAMILY_NAME, mlDsaAlgo, pkey);
        }

        public JceMlDsaPublicKey(String mlDsaAlgo, Pkey pkey, byte[] encoding) {
            super(ML_DSA_ALGO_FAMILY_NAME, mlDsaAlgo, pkey, encoding);
        }

        @Override
        public String getAlgorithm() {
            return ML_DSA_ALGO_FAMILY_NAME;
        }
    }
}
