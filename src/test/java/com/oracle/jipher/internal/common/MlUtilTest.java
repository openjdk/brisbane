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

package com.oracle.jipher.internal.common;

import java.security.InvalidKeyException;
import java.util.List;

import org.junit.Test;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jipher.internal.asn1.Asn1.implicit;
import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newRcsUTF8String;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.Asn1.newSetOf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;



public class MlUtilTest {

    static byte[] makePrivate(byte[] encodedPrivateKey, byte[] encodedPublicKey, boolean withAttributes, boolean withPublicKey) {
        Asn1BerValue oneAsymmetricKey = Asn1.decodeOne(encodedPrivateKey).count(3);
        List<Asn1BerValue> members = oneAsymmetricKey.sequence();
        assertEquals(0, members.get(0).getInteger().intValueExact());

        byte[] rawPublicKey = Asn1.decodeOne(encodedPublicKey).count(2).sequence().get(1).getBitStringOctets();

        Asn1BerValue attributes = withAttributes ?
                implicit(0).newSetOf(newSequence(
                    newOid("1.2.840.113549.1.9.20"),
                    newSetOf(newRcsUTF8String("My ML-DSA Key"))
                )) : null;

        return newSequence(
                // version Version -- V1 or V2 depending on whether publicKey is present
                newInteger(withPublicKey ? 1 : 0),
                // alg id
                members.get(1),
                // privateKey octet string
                members.get(2),
                attributes,
                withPublicKey ? implicit(1).newBitString(rawPublicKey) : null
        ).encodeDerOctets();
    }

    @Test
    public void decodeMlKemPrivateV1WithAttributes() throws Exception {
        KeyPairTestData mlKemTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM").secParam("ML-KEM-768"));
        MlUtil.PrivateKeyData prvDataFromV1 = MlUtil.decodePrivateKey(mlKemTestData.getPriv());
        assertEquals(0, prvDataFromV1.version());

        byte[] v1KeyWithAttibutes = makePrivate(mlKemTestData.getPriv(), mlKemTestData.getPub(), true, false);
        MlUtil.PrivateKeyData prvDataFromV1WithAttributes = MlUtil.decodePrivateKey(v1KeyWithAttibutes);
        assertEquals(0, prvDataFromV1WithAttributes.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV1WithAttributes.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV1WithAttributes.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV1WithAttributes.expandedKey());
    }

    @Test
    public void decodeMlDsaPrivateV1WithAttributes() throws Exception {
        KeyPairTestData mlDsaTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-DSA").secParam("ML-DSA-65"));
        MlUtil.PrivateKeyData prvDataFromV1 = MlUtil.decodePrivateKey(mlDsaTestData.getPriv());
        assertEquals(0, prvDataFromV1.version());

        byte[] v1KeyWithAttibutes = makePrivate(mlDsaTestData.getPriv(), mlDsaTestData.getPub(), true, false);
        MlUtil.PrivateKeyData prvDataFromV1WithAttributes = MlUtil.decodePrivateKey(v1KeyWithAttibutes);
        assertEquals(0, prvDataFromV1WithAttributes.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV1WithAttributes.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV1WithAttributes.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV1WithAttributes.expandedKey());
    }

    @Test
    public void decodeMlKemPrivateV2() throws Exception {
        KeyPairTestData mlKemTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-KEM").secParam("ML-KEM-768"));
        MlUtil.PrivateKeyData prvDataFromV1 = MlUtil.decodePrivateKey(mlKemTestData.getPriv());
        assertEquals(0, prvDataFromV1.version());

        byte[] v2Key = makePrivate(mlKemTestData.getPriv(), mlKemTestData.getPub(), false, true);
        MlUtil.PrivateKeyData prvDataFromV2 = MlUtil.decodePrivateKey(v2Key);
        assertEquals(1, prvDataFromV2.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV2.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV2.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV2.expandedKey());

        byte[] v2KeyWithAttributes = makePrivate(mlKemTestData.getPriv(), mlKemTestData.getPub(), true, true);
        MlUtil.PrivateKeyData prvDataFromV2WithAttributes = MlUtil.decodePrivateKey(v2KeyWithAttributes);
        assertEquals(1, prvDataFromV2WithAttributes.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV2WithAttributes.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV2WithAttributes.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV2WithAttributes.expandedKey());
    }

    @Test
    public void decodeMlDsaPrivateV2() throws Exception {
        KeyPairTestData mlDsaTestData = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("ML-DSA").secParam("ML-DSA-65"));
        MlUtil.PrivateKeyData prvDataFromV1 = MlUtil.decodePrivateKey(mlDsaTestData.getPriv());
        assertEquals(0, prvDataFromV1.version());

        byte[] v2Key = makePrivate(mlDsaTestData.getPriv(), mlDsaTestData.getPub(), false, true);
        MlUtil.PrivateKeyData prvDataFromV2 = MlUtil.decodePrivateKey(v2Key);
        assertEquals(1, prvDataFromV2.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV2.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV2.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV2.expandedKey());

        byte[] v2KeyWithAttributes = makePrivate(mlDsaTestData.getPriv(), mlDsaTestData.getPub(), true, true);
        MlUtil.PrivateKeyData prvDataFromV2WithAttributes = MlUtil.decodePrivateKey(v2KeyWithAttributes);
        assertEquals(1, prvDataFromV2WithAttributes.version());
        assertEquals(prvDataFromV1.algOid(), prvDataFromV2WithAttributes.algOid());
        assertArrayEquals(prvDataFromV1.seed(), prvDataFromV2WithAttributes.seed());
        assertArrayEquals(prvDataFromV1.expandedKey(), prvDataFromV2WithAttributes.expandedKey());
    }

    @Test(expected = InvalidKeyException.class)
    public void decodePublicKeyNeg() throws Exception {
        MlUtil.decodePublicKey(newRcsUTF8String("xyzzy").encodeDerOctets());
    }
}
