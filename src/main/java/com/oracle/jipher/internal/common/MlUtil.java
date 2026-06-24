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

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;

import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.asn1.UniversalTag.OCTET_STRING;

public class MlUtil {

    private MlUtil() {
    }

    /*
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm AlgorithmIdentifier,
     *   subjectPublicKey BIT STRING
     * }
     */
    public static PublicKeyData decodePublicKey(byte[] encodedKey) throws InvalidKeyException {
        try {
            // SubjectPublicKeyInfo
            List<Asn1BerValue> subPubKeyInfo = Asn1.decodeOne(encodedKey, true).count(2)
                    .tagClassDeep(UNIVERSAL).sequence();

            // algorithm AlgorithmIdentifier
            // AlgorithmIdentifier ::= SEQUENCE {
            //   algorithm OBJECT IDENTIFIER,
            //   parameters ANY OPTIONAL -- must not be present for ML-KEM/ML-DSA public keys
            // }
            String algOid = subPubKeyInfo.get(0).count(1).sequence().get(0).getOid();

            // subjectPublicKey BIT STRING
            byte[] rawPublicKey = subPubKeyInfo.get(1).getBitStringOctets();
            return new PublicKeyData(algOid, rawPublicKey);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode ML-KEM/ML-DSA Public key", ex);
        }
    }

    /*
     * OneAsymmetricKey ::= SEQUENCE {
     *     version                   Version,
     *     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *     privateKey                PrivateKey,
     *     attributes            [0] Attributes OPTIONAL,
     *     ...,
     *     [[2: publicKey        [1] PublicKey OPTIONAL ]],
     *     ...
     * }
     *
     * See <a href="https://www.rfc-editor.org/rfc/rfc9935.html#name-private-key-format">RFC 9935 Section 6. Private Key Format</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc9881.html#name-private-key-format">RFC 9881 Section 6. Private Key Format</a>.
     */
    public static PrivateKeyData decodePrivateKey(byte[] encodedKey) throws InvalidKeyException {
        byte[] prvKey = null;
        byte[] decodedSeed = null;
        try {
            // OneAsymmetricKey ::= SEQUENCE
            Asn1BerValue oneAsymmetricKey = Asn1.decodeOne(encodedKey, true).count(3, 5);
            List<Asn1BerValue> members = oneAsymmetricKey.sequence();

            // version Version
            int version = members.get(0).getInteger().intValueExact();
            boolean publicPresent = switch (version) {
                case 0 -> false; // V1
                case 1 -> true;  // V2
                default -> throw new InvalidKeyException("Unsupported version of ML-KEM/ML-DSA key " + version);
            };
            boolean attributesPresent;
            if (publicPresent) {
                oneAsymmetricKey.count(4, 5);
                attributesPresent = members.size() == 5;
            } else {
                oneAsymmetricKey.maxCount(4);
                attributesPresent = members.size() == 4;
            }

            // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
            // PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
            // AlgorithmIdentifier ::= SEQUENCE {
            //   algorithm OBJECT IDENTIFIER,
            //   parameters ANY OPTIONAL -- must not be present for ML-KEM/ML-DSA public keys
            // }
            String algOid = members.get(1).count(1).sequence().get(0).getOid();

            // privateKey PrivateKey
            prvKey = members.get(2).getOctetString();

            // attributes [0] Attributes OPTIONAL
            if (attributesPresent) {
                // Attributes ::= SET OF Attribute
                members.get(3).tag(0).constructed();
            }

            // [[2: publicKey        [1] PublicKey OPTIONAL ]]
            if (publicPresent) {
                members.get(members.size() - 1).tag(1).primitive();
            }

            Asn1BerValue prvKeyChoice = Asn1.decodeOne(prvKey, true);
            byte[] seed = null;
            byte[] expandedKey = null;
            if (prvKeyChoice.hasTag(0)) {
                seed = prvKeyChoice.octets();
            } else if (prvKeyChoice.hasTag(OCTET_STRING)) {
                expandedKey = prvKeyChoice.getOctetString();
            } else {
                // both
                List<Asn1BerValue> seedAndExpandedKey = prvKeyChoice.count(2).tagClassDeep(UNIVERSAL).sequence();
                decodedSeed = seedAndExpandedKey.get(0).getOctetString();
                expandedKey = seedAndExpandedKey.get(1).getOctetString();
                seed = decodedSeed;
                decodedSeed = null; // prevent clearing
            }
            return new PrivateKeyData(version, algOid, seed, expandedKey);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode ML-KEM/ML-DSA Private key", ex);
        } finally {
            Util.clearArrays(prvKey, decodedSeed);
        }
    }

    public record PublicKeyData(String algOid, byte[] pubKeyPayload) {
    }

    public record PrivateKeyData(int version, String algOid, byte[] seed, byte[] expandedKey) {
    }
}
