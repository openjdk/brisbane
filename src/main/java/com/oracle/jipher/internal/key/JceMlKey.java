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

import java.util.Optional;

import com.oracle.jipher.internal.asn1.Asn1BerValue;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;


/**
 * Interface for Module-Lattice keys.
 * <p>
 * Defines supported Module-Lattice Key variants {ML-KEM, ML-DSA}, algorithm names and
 * object identifiers.
 * </p>
 * <p>
 * Provides a method for looking up the details of an ML algorithm
 * by name or OID.
 * </p>
 */
public sealed interface JceMlKey permits JceMlPrivateKey, JceMlPublicKey {

    enum Algorithm {
        ML_KEM_512(STR_ML_KEM_512, STR_ML_KEM_512_OID, ML_KEM_ALGO_FAMILY_NAME, 64, 1632),
        ML_KEM_768(STR_ML_KEM_768, STR_ML_KEM_768_OID, ML_KEM_ALGO_FAMILY_NAME, 64, 2400),
        ML_KEM_1024(STR_ML_KEM_1024, STR_ML_KEM_1024_OID, ML_KEM_ALGO_FAMILY_NAME, 64, 3168),

        ML_DSA_44(STR_ML_DSA_44, STR_ML_DSA_44_OID, ML_DSA_ALGO_FAMILY_NAME, 32, 2560),
        ML_DSA_65(STR_ML_DSA_65, STR_ML_DSA_65_OID, ML_DSA_ALGO_FAMILY_NAME, 32, 4032),
        ML_DSA_87(STR_ML_DSA_87, STR_ML_DSA_87_OID, ML_DSA_ALGO_FAMILY_NAME, 32, 4896);

        private final String algName;
        private final String algOID;
        private final String algFamilyName;
        private final int seedSize;
        private final int expandedKeySize;

        Algorithm(String name, String oid, String familyName, int seedSize, int expandedKeySize) {
            this.algName = name;
            this.algOID = oid;
            this.algFamilyName = familyName;
            this.seedSize = seedSize;
            this.expandedKeySize = expandedKeySize;
        }

        public String getAlgName() {
            return this.algName;
        }

        public String getAlgOID() {
            return this.algOID;
        }

        public String getAlgFamilyName() {
            return this.algFamilyName;
        }

        public int getSeedSize() {
            return this.seedSize;
        }

        public int getExpandedKeySize() {
            return this.expandedKeySize;
        }
    }

    String ML_KEM_ALGO_FAMILY_NAME = "ML-KEM";
    String ML_DSA_ALGO_FAMILY_NAME = "ML-DSA";

    String STR_ML_KEM_512_OID = "2.16.840.1.101.3.4.4.1";
    String STR_ML_KEM_768_OID = "2.16.840.1.101.3.4.4.2";
    String STR_ML_KEM_1024_OID = "2.16.840.1.101.3.4.4.3";

    String STR_ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17";
    String STR_ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18";
    String STR_ML_DSA_87_OID = "2.16.840.1.101.3.4.3.19";

    String STR_ML_KEM_512 = "ML-KEM-512";
    String STR_ML_KEM_768 = "ML-KEM-768";
    String STR_ML_KEM_1024 = "ML-KEM-1024";

    String STR_ML_DSA_44 = "ML-DSA-44";
    String STR_ML_DSA_65 = "ML-DSA-65";
    String STR_ML_DSA_87 = "ML-DSA-87";

    default Asn1BerValue getAlgId(String alg) {
        return newOid(getStrAlgId(alg));
    }

    static Optional<Algorithm> find(String id) {
        Algorithm[] all = Algorithm.values();
        for (Algorithm alg : all) {
            if (alg.getAlgName().equalsIgnoreCase(id) || alg.getAlgOID().equals(id)) {
                return Optional.of(alg);
            }
        }
        return Optional.empty();
    }

    static String getStrAlgId(String alg) {
        return switch (alg) {
            case STR_ML_KEM_1024 -> STR_ML_KEM_1024_OID;
            case STR_ML_KEM_768 -> STR_ML_KEM_768_OID;
            case STR_ML_KEM_512 -> STR_ML_KEM_512_OID;
            case STR_ML_DSA_44 -> STR_ML_DSA_44_OID;
            case STR_ML_DSA_65 -> STR_ML_DSA_65_OID;
            case STR_ML_DSA_87 -> STR_ML_DSA_87_OID;
            default -> throw new IllegalArgumentException("Invalid ML algorithm type " + alg);
        };
    }

    String variant();
}
