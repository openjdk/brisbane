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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.KEM;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class PairwiseHelper {

    static void pairwiseConsistency(PublicKey pub, PrivateKey priv) throws Exception {
        String keyAlgo = pub.getAlgorithm();
        if ("DH".equals(keyAlgo)) {
            DHPublicKey dhPub = (DHPublicKey) pub;
            DHPrivateKey dhPriv = (DHPrivateKey) priv;
            assertEquals(dhPub.getParams().getG().modPow(dhPriv.getX(), dhPub.getParams().getP()), dhPub.getY());
        } else if ("ML-KEM".equals(keyAlgo)) {
            KEM me = ProviderUtil.getKEM(keyAlgo);
            Encapsulator encapsulator = me.newEncapsulator(pub);
            Encapsulated encapsulated = encapsulator.encapsulate();
            SecretKey localShare = encapsulated.key();
            byte[] forPeer = encapsulated.encapsulation();

            KEM peer = ProviderUtil.getKEM(keyAlgo);
            Decapsulator decapsulator = peer.newDecapsulator(priv);
            SecretKey peerShare = decapsulator.decapsulate(forPeer);
            assertEquals(localShare, peerShare);

        } else {
            Signature sig = ProviderUtil.getSignature(sigAlg(pub.getAlgorithm()));
            sig.initSign(priv);
            // Test with random data instead of static values.
            Random rand = ThreadLocalRandom.current();
            byte[] testData = new byte[10];
            rand.nextBytes(testData);
            sig.update(testData);
            byte[] signature = sig.sign();

            sig.initVerify(pub);
            sig.update(testData);
            assertTrue("Failed for " + TestUtil.bytesToHex(testData), sig.verify(signature));
        }
    }

    private static String sigAlg(String alg) {
        return switch (alg) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "DSA" -> "SHA224withDSA";
            case "ML-DSA" -> "ML-DSA";
            default -> throw new Error("Pairwise test not implemented.");
        };
    }
}
