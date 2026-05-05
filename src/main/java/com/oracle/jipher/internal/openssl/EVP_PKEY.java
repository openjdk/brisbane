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

package com.oracle.jipher.internal.openssl;

import java.util.function.Consumer;

import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_ALGORITHM_ID;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_ALGORITHM_ID_PARAMS;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_CIPHER;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_DIGEST;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_FIPS_APPROVED_INDICATOR;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_PROPERTIES;

public interface EVP_PKEY extends OsslSetParams {

    /* PKEY parameters */
    /* Common PKEY parameters */
    String PKEY_PARAM_ALGORITHM_ID        = ALG_PARAM_ALGORITHM_ID; /* octet_string */
    String PKEY_PARAM_ALGORITHM_ID_PARAMS = ALG_PARAM_ALGORITHM_ID_PARAMS; /* octet_string */
    String PKEY_PARAM_BITS                = "bits"; /* integer */
    String PKEY_PARAM_CIPHER              = ALG_PARAM_CIPHER; /* utf8_string */
    String PKEY_PARAM_DEFAULT_DIGEST      = "default-digest"; /* utf8_string */
    String PKEY_PARAM_DIGEST              = ALG_PARAM_DIGEST;
    String PKEY_PARAM_DIGEST_SIZE         = "digest-size";
    String PKEY_PARAM_DIST_ID             = "distid";
    String PKEY_PARAM_ENCODED_PUBLIC_KEY  = "encoded-pub-key";
    String PKEY_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR; /* int, 0 or 1 */
    String PKEY_PARAM_FIPS_DIGEST_CHECK   = "digest-check"; /* int, 0 or 1 */
    String PKEY_PARAM_FIPS_KEY_CHECK      = "key-check"; /* int, 0 or 1 */
    String PKEY_PARAM_FIPS_SIGN_CHECK     = "sign-check"; /* int, 0 or 1 */
    String PKEY_PARAM_GROUP_NAME          = "group";
    String PKEY_PARAM_MANDATORY_DIGEST    = "mandatory-digest"; /* utf8_string */
    String PKEY_PARAM_MASKGENFUNC         = "mgf";
    String PKEY_PARAM_MAX_SIZE            = "max-size"; /* int */
    String PKEY_PARAM_MGF1_DIGEST         = "mgf1-digest";
    String PKEY_PARAM_MGF1_PROPERTIES     = "mgf1-properties";
    String PKEY_PARAM_PAD_MODE            = "pad-mode";
    String PKEY_PARAM_PRIV_KEY            = "priv";
    String PKEY_PARAM_PROPERTIES          = ALG_PARAM_PROPERTIES;
    String PKEY_PARAM_PUB_KEY             = "pub";
    String PKEY_PARAM_SECURITY_BITS       = "security-bits"; /* int */

    /* Diffie-Hellman/DSA Parameters */
    String PKEY_PARAM_FFC_P               = "p";
    String PKEY_PARAM_FFC_G               = "g";
    String PKEY_PARAM_FFC_Q               = "q";
    String PKEY_PARAM_FFC_GINDEX          = "gindex";
    String PKEY_PARAM_FFC_PCOUNTER        = "pcounter";
    String PKEY_PARAM_FFC_SEED            = "seed";
    String PKEY_PARAM_FFC_COFACTOR        = "j";
    String PKEY_PARAM_FFC_H               = "hindex";
    String PKEY_PARAM_FFC_VALIDATE_PQ     = "validate-pq";
    String PKEY_PARAM_FFC_VALIDATE_G      = "validate-g";
    String PKEY_PARAM_FFC_VALIDATE_LEGACY = "validate-legacy";

    /* Diffie-Hellman params */
    String PKEY_PARAM_DH_GENERATOR        = "safeprime-generator";
    String PKEY_PARAM_DH_PRIV_LEN         = "priv_len";

    /* Elliptic Curve Domain Parameters */
    String PKEY_PARAM_EC_PUB_X            = "qx";
    String PKEY_PARAM_EC_PUB_Y            = "qy";

    /* Elliptic Curve Explicit Domain Parameters */
    String PKEY_PARAM_EC_FIELD_TYPE       = "field-type";
    String PKEY_PARAM_EC_P                = "p";
    String PKEY_PARAM_EC_A                = "a";
    String PKEY_PARAM_EC_B                = "b";
    String PKEY_PARAM_EC_GENERATOR        = "generator";
    String PKEY_PARAM_EC_ORDER            = "order";
    String PKEY_PARAM_EC_COFACTOR         = "cofactor";
    String PKEY_PARAM_EC_SEED             = "seed";
    String PKEY_PARAM_EC_CHAR2_M          = "m";
    String PKEY_PARAM_EC_CHAR2_TYPE       = "basis-type";
    String PKEY_PARAM_EC_CHAR2_TP_BASIS   = "tp";
    String PKEY_PARAM_EC_CHAR2_PP_K1      = "k1";
    String PKEY_PARAM_EC_CHAR2_PP_K2      = "k2";
    String PKEY_PARAM_EC_CHAR2_PP_K3      = "k3";
    String PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS = "decoded-from-explicit";

    /* Elliptic Curve Key Parameters */
    String PKEY_PARAM_USE_COFACTOR_FLAG = "use-cofactor-flag";
    String PKEY_PARAM_USE_COFACTOR_ECDH = PKEY_PARAM_USE_COFACTOR_FLAG;

    /* RSA Keys */
    /*
     * n, e, d are the usual public and private key components
     *
     * rsa-num is the number of factors, including p and q
     * rsa-factor is used for each factor: p, q, r_i (i  = 3, ...);
     * rsa-exponent is used for each exponent: dP, dQ, d_i (i  = 3, ...);
     * rsa-coefficient is used for each coefficient: qInv, t_i (i  = 3, ...);
     *
     * The number of rsa-factor items must be equal to the number of rsa-exponent
     * items, and the number of rsa-coefficients must be one less.
     * (the base i for the coefficients is 2, not 1, at least as implied by
     * RFC 8017)
     */
    String PKEY_PARAM_RSA_N            = "n";
    String PKEY_PARAM_RSA_E            = "e";
    String PKEY_PARAM_RSA_D            = "d";
    String PKEY_PARAM_RSA_FACTOR       = "rsa-factor";
    String PKEY_PARAM_RSA_EXPONENT     = "rsa-exponent";
    String PKEY_PARAM_RSA_COEFFICIENT  = "rsa-coefficient";
    String PKEY_PARAM_RSA_FACTOR1      = PKEY_PARAM_RSA_FACTOR + "1";
    String PKEY_PARAM_RSA_FACTOR2      = PKEY_PARAM_RSA_FACTOR + "2";
    String PKEY_PARAM_RSA_FACTOR3      = PKEY_PARAM_RSA_FACTOR + "3";
    String PKEY_PARAM_RSA_FACTOR4      = PKEY_PARAM_RSA_FACTOR + "4";
    String PKEY_PARAM_RSA_FACTOR5      = PKEY_PARAM_RSA_FACTOR + "5";
    String PKEY_PARAM_RSA_FACTOR6      = PKEY_PARAM_RSA_FACTOR + "6";
    String PKEY_PARAM_RSA_FACTOR7      = PKEY_PARAM_RSA_FACTOR + "7";
    String PKEY_PARAM_RSA_FACTOR8      = PKEY_PARAM_RSA_FACTOR + "8";
    String PKEY_PARAM_RSA_FACTOR9      = PKEY_PARAM_RSA_FACTOR + "9";
    String PKEY_PARAM_RSA_FACTOR10     = PKEY_PARAM_RSA_FACTOR + "10";
    String PKEY_PARAM_RSA_EXPONENT1    = PKEY_PARAM_RSA_EXPONENT + "1";
    String PKEY_PARAM_RSA_EXPONENT2    = PKEY_PARAM_RSA_EXPONENT + "2";
    String PKEY_PARAM_RSA_EXPONENT3    = PKEY_PARAM_RSA_EXPONENT + "3";
    String PKEY_PARAM_RSA_EXPONENT4    = PKEY_PARAM_RSA_EXPONENT + "4";
    String PKEY_PARAM_RSA_EXPONENT5    = PKEY_PARAM_RSA_EXPONENT + "5";
    String PKEY_PARAM_RSA_EXPONENT6    = PKEY_PARAM_RSA_EXPONENT + "6";
    String PKEY_PARAM_RSA_EXPONENT7    = PKEY_PARAM_RSA_EXPONENT + "7";
    String PKEY_PARAM_RSA_EXPONENT8    = PKEY_PARAM_RSA_EXPONENT + "8";
    String PKEY_PARAM_RSA_EXPONENT9    = PKEY_PARAM_RSA_EXPONENT + "9";
    String PKEY_PARAM_RSA_EXPONENT10   = PKEY_PARAM_RSA_EXPONENT + "10";
    String PKEY_PARAM_RSA_COEFFICIENT1 = PKEY_PARAM_RSA_COEFFICIENT + "1";
    String PKEY_PARAM_RSA_COEFFICIENT2 = PKEY_PARAM_RSA_COEFFICIENT + "2";
    String PKEY_PARAM_RSA_COEFFICIENT3 = PKEY_PARAM_RSA_COEFFICIENT + "3";
    String PKEY_PARAM_RSA_COEFFICIENT4 = PKEY_PARAM_RSA_COEFFICIENT + "4";
    String PKEY_PARAM_RSA_COEFFICIENT5 = PKEY_PARAM_RSA_COEFFICIENT + "5";
    String PKEY_PARAM_RSA_COEFFICIENT6 = PKEY_PARAM_RSA_COEFFICIENT + "6";
    String PKEY_PARAM_RSA_COEFFICIENT7 = PKEY_PARAM_RSA_COEFFICIENT + "7";
    String PKEY_PARAM_RSA_COEFFICIENT8 = PKEY_PARAM_RSA_COEFFICIENT + "8";
    String PKEY_PARAM_RSA_COEFFICIENT9 = PKEY_PARAM_RSA_COEFFICIENT + "9";

    /* RSA padding modes */
    String PKEY_RSA_PAD_MODE_NONE    = "none";
    String PKEY_RSA_PAD_MODE_PKCSV15 = "pkcs1";
    String PKEY_RSA_PAD_MODE_OAEP    = "oaep";
    String PKEY_RSA_PAD_MODE_X931    = "x931";
    String PKEY_RSA_PAD_MODE_PSS     = "pss";

    /* RSA pss padding salt length */
    String PKEY_RSA_PSS_SALT_LEN_DIGEST = "digest";
    String PKEY_RSA_PSS_SALT_LEN_MAX    = "max";
    String PKEY_RSA_PSS_SALT_LEN_AUTO   = "auto";
    String PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX = "auto-digestmax";

    /* Key generation parameters */
    String PKEY_PARAM_RSA_BITS             = PKEY_PARAM_BITS;
    String PKEY_PARAM_RSA_PRIMES           = "primes";
    String PKEY_PARAM_RSA_DIGEST           = PKEY_PARAM_DIGEST;
    String PKEY_PARAM_RSA_DIGEST_PROPS     = PKEY_PARAM_PROPERTIES;
    String PKEY_PARAM_RSA_MASKGENFUNC      = PKEY_PARAM_MASKGENFUNC;
    String PKEY_PARAM_RSA_MGF1_DIGEST      = PKEY_PARAM_MGF1_DIGEST;
    String PKEY_PARAM_RSA_PSS_SALTLEN      = "saltlen";
    String PKEY_PARAM_RSA_DERIVE_FROM_PQ   = "rsa-derive-from-pq";

    /* Key generation parameters */
    String PKEY_PARAM_FFC_TYPE         = "type";
    String PKEY_PARAM_FFC_PBITS        = "pbits";
    String PKEY_PARAM_FFC_QBITS        = "qbits";
    String PKEY_PARAM_FFC_DIGEST       = PKEY_PARAM_DIGEST;
    String PKEY_PARAM_FFC_DIGEST_PROPS = PKEY_PARAM_PROPERTIES;

    String PKEY_PARAM_EC_ENCODING                = "encoding"; /* utf8_string */
    String PKEY_PARAM_EC_POINT_CONVERSION_FORMAT = "point-format";
    String PKEY_PARAM_EC_GROUP_CHECK_TYPE        = "group-check";
    String PKEY_PARAM_EC_INCLUDE_PUBLIC          = "include-public";
    String PKEY_PARAM_DHKEM_IKM                  = "dhkem-ikm"; /* octet_string */

    /* OSSL_PKEY_PARAM_EC_ENCODING values */
    String PKEY_EC_ENCODING_EXPLICIT  = "explicit";
    String PKEY_EC_ENCODING_GROUP     = "named_curve";

    String PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED = "uncompressed";
    String PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED   = "compressed";
    String PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID       = "hybrid";

    String PKEY_EC_GROUP_CHECK_DEFAULT     = "default";
    String PKEY_EC_GROUP_CHECK_NAMED       = "named";
    String PKEY_EC_GROUP_CHECK_NAMED_NIST  = "named-nist";

    /* Asymmetric Cipher parameters */
    String ASYM_CIPHER_PARAM_DIGEST             = PKEY_PARAM_DIGEST;
    String ASYM_CIPHER_PARAM_IMPLICIT_REJECTION = "implicit-rejection";
    String ASYM_CIPHER_PARAM_MGF1_DIGEST        = PKEY_PARAM_MGF1_DIGEST;
    String ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS  = PKEY_PARAM_MGF1_PROPERTIES;
    String ASYM_CIPHER_PARAM_OAEP_DIGEST        = ALG_PARAM_DIGEST;
    String ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS  = "digest-props";
    String ASYM_CIPHER_PARAM_OAEP_LABEL         = "oaep-label";
    String ASYM_CIPHER_PARAM_PAD_MODE           = PKEY_PARAM_PAD_MODE;
    String ASYM_CIPHER_PARAM_PROPERTIES         = PKEY_PARAM_PROPERTIES;

    /* Key Exchange parameters */
    String EXCHANGE_PARAM_PAD                   = "pad";                /* uint */
    String EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE = "ecdh-cofactor-mode"; /* int */
    String EXCHANGE_PARAM_KDF_TYPE              = "kdf-type";           /* utf8_string */
    String EXCHANGE_PARAM_KDF_DIGEST            = "kdf-digest";         /* utf8_string */
    String EXCHANGE_PARAM_KDF_DIGEST_PROPS      = "kdf-digest-props";   /* utf8_string */
    String EXCHANGE_PARAM_KDF_OUTLEN            = "kdf-outlen";         /* size_t */
    /* The following parameter is an octet_string on set and an octet_ptr on get */
    String EXCHANGE_PARAM_KDF_UKM               = "kdf-ukm";

    /* ML-* seed parameter for ML-KEM and ML-DSA */
    String PKEY_PARAM_ML_SEED           = "seed";                   /* octet_string */

    /* ML-DSA parameters */
    String PKEY_PARAM_ML_DSA_INPUT_FORMATS  = "ml-dsa.input_formats";   /* utf8_string */
    String PKEY_PARAM_ML_DSA_OUTPUT_FORMATS = "ml-dsa.output_formats";  /* utf8_string */
    String PKEY_PARAM_ML_DSA_PREFER_SEED    = "ml-dsa.prefer_seed";     /* utf8_string */
    String PKEY_PARAM_ML_DSA_RETAIN_SEED    = "ml-dsa.retain_seed";     /* utf8_string */
    String PKEY_PARAM_ML_DSA_SEED           = PKEY_PARAM_ML_SEED;       /* octet_string */

    /* ML-KEM parameters */
    String PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE = "ml-kem.import_pct_type"; /* utf8_string */
    String PKEY_PARAM_ML_KEM_INPUT_FORMATS   = "ml-kem.input_formats";  /* utf8_string */
    String PKEY_PARAM_ML_KEM_OUTPUT_FORMATS  = "ml-kem.output_formats"; /* utf8_string */
    String PKEY_PARAM_ML_KEM_PREFER_SEED     = "ml-kem.prefer_seed";    /* utf8_string */
    String PKEY_PARAM_ML_KEM_RETAIN_SEED     = "ml-kem.retain_seed";    /* utf8_string */
    String PKEY_PARAM_ML_KEM_SEED            = PKEY_PARAM_ML_SEED;      /* octet_string */

    /* SLH-DSA parameters */
    String PKEY_PARAM_SLH_DSA_SEED = "seed"; /* octet_string */

    /* Special values for PKEY_PARAM_RSA_PSS_SALTLEN */
    int PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_DIGEST          = -1;
    int PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_AUTO            = -2;
    int PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_MAX             = -3;
    int PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_AUTO_DIGEST_MAX = -4;

    /* The following are limits defined in rsa.h */
    int RSA_SMALL_MODULUS_BITS= 3072;
    int RSA_MAX_PUBEXP_BITS = 64;

    enum Selection {
        KEY_PARAMETERS(0x84),
        PUBLIC_KEY(0x86),
        PKEY_KEYPAIR(0x87);

        public final int mask;

        Selection(int mask) {
            this.mask = mask;
        }
    }

    void free();

    default EVP_PKEY upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_PKEY upRef(OsslArena arena);

    default EVP_PKEY dup() {
        return dup(OsslArena.ofAuto());
    }
    EVP_PKEY dup(OsslArena arena);

    boolean isA(String name);
    boolean forEachTypeName(Consumer<String> consumer);
    String typeName();
    String description();
    String providerName();

    OsslParamBuffer todata(Selection selection, OsslArena osslArena);
    default OSSL_PARAM[] todata(Selection selection) {
        try (OsslArena arena = OsslArena.ofConfined()) {
            return todata(selection, arena).asArray();
        }
    }
}
