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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


public class KeyPairSerializeTest {

    private static final String MLKEM_ENC_PROP = "jdk.mlkem.pkcs8.encoding";
    private static final String MLDSA_ENC_PROP = "jdk.mldsa.pkcs8.encoding";
    private static String MLKEM_ENC_VAL;
    private static String MLDSA_ENC_VAL;

    @BeforeAll
    public static void setup() {
        MLKEM_ENC_VAL = System.getProperty(MLKEM_ENC_PROP);
        MLDSA_ENC_VAL = System.getProperty(MLDSA_ENC_PROP);
        // Set this to allow JDK providers to deserialize.
        System.setProperty(MLKEM_ENC_PROP, "expandedKey");
        System.setProperty(MLDSA_ENC_PROP, "expandedKey");
    }

    public static Collection<String> params()  {
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

    @ParameterizedTest
    @MethodSource("params")
    public void serializeDeserializeTest(String alg) throws Exception {
        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(alg);
        KeyPair keyPair = kpg.generateKeyPair();

        if ("DH".equals(alg) && Security.getProvider("JipherJCE") == null) {
            // The SunJCE's DH KeyFactory does not support the dhpublicnumber DH parameter encoding in RFC 3279
            // which accommodates Q. It only supports the dhKeyAgreement DH parameter encoding in PKCS #3 section 9
            // which omits Q.  Hence we have to update the DH key to remove Q.
            keyPair = removeQ(keyPair);
        }

        ByteArrayOutputStream baOut = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(baOut);
        objOut.writeObject(keyPair);

        ByteArrayInputStream baIn = new ByteArrayInputStream(baOut.toByteArray());
        ObjectInputStream objIn = new ObjectInputStream(baIn);
        KeyPair deserializedKeyPair = (KeyPair) objIn.readObject();

        checkKeyPair(keyPair, deserializedKeyPair);
    }

    void checkKeyPair(KeyPair expected, KeyPair actual) throws Exception {
        String alg = expected.getPrivate().getAlgorithm();
        // PQC Key classes are not part of public API in JDK.
        if ("ML-KEM".equals(alg) || "ML-DSA".equals(alg)) {
            assertArrayEquals(expected.getPrivate().getEncoded(), actual.getPrivate().getEncoded());
        } else {
            assertEquals(expected.getPrivate(), actual.getPrivate());
            assertEquals(expected.getPublic(), actual.getPublic());
        }
    }

    // Removes Q from a DH key pair
    KeyPair removeQ(KeyPair keyPair) throws Exception {
        KeyFactory kf = ProviderUtil.getKeyFactory("DH");
        KeySpec pubKeySpec =  kf.getKeySpec(keyPair.getPublic(), DHPublicKeySpec.class);
        KeySpec priKeySpec =  kf.getKeySpec(keyPair.getPrivate(), DHPrivateKeySpec.class);
        return new KeyPair(kf.generatePublic(pubKeySpec), kf.generatePrivate(priKeySpec));
    }

    @AfterAll
    public static void tearDown() {
        if (MLDSA_ENC_VAL == null) {
            System.clearProperty(MLDSA_ENC_PROP);
        } else {
            System.setProperty(MLDSA_ENC_PROP, MLDSA_ENC_VAL);
        }
        if (MLKEM_ENC_VAL == null) {
            System.clearProperty(MLKEM_ENC_PROP);
        } else {
            System.setProperty(MLKEM_ENC_PROP, MLKEM_ENC_VAL);
        }
    }
}
