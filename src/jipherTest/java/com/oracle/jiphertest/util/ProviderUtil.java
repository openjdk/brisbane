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

package com.oracle.jiphertest.util;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.ServiceLoader;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

/**
 * This class provides a single place to access a Provider to use for testing.
 */
public class ProviderUtil {

    private static Provider instance;
    private static final String PROV_STRING = "JipherJCE";

    private static final ProvUsage PROV_USAGE;

    enum ProvUsage {
        INSTANCE, // Indicates getInstance methods should specify provider by instance
        FIRST, // Indicates getInstance shall not specify provider.
        STRING, // Indicates getInstance shall specify provider by String
        DYNAMIC_FIRST, // Indicates provider should be added dynamically at first position, then not specified
        DYNAMIC_STRING // Indicates provider should be added dynamically, then specified by String.
    }

    static {
        try {
            PROV_USAGE = ProvUsage.valueOf(System.getProperty("provider.test.mode", "instance").toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new Error("Testing property 'provider.test.mode' contained unrecognised value, "
                    + "expected one of " + Arrays.asList(ProvUsage.values()));
        }
        Provider provider = getJipherInstanceViaServiceLoader();
        if (PROV_USAGE == ProvUsage.DYNAMIC_FIRST) {
            Security.insertProviderAt(provider, 1);
        } else if (PROV_USAGE == ProvUsage.DYNAMIC_STRING) {
            Security.addProvider(provider);
        } else if (PROV_USAGE == ProvUsage.INSTANCE) {
            // Its important only to create the provider instance provider when test configuration
            // specifies because the provider tests try to test first usage of the provider by
            // the JCE framework.
            instance = provider;
        }
    }

    static Provider getJipherInstanceViaServiceLoader() {
        return ServiceLoader.load(Provider.class)
                .stream()
                .map(ServiceLoader.Provider::get)
                .filter(provider -> provider.getName().equals("JipherJCE"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("JipherJCE provider not found"));
    }

    public static Provider get() {
        if (instance != null) {
            return instance;
        }
        return Security.getProvider("JipherJCE");
    }

    public static String getProviderConfig() {
        String fullProperty = System.getProperty("java.security.properties");
        if (fullProperty == null || fullProperty.isEmpty()) {
            return "NoReg-" + PROV_USAGE.name();
        }
        String config = System.getProperty("java.security.properties")
                .substring(fullProperty.lastIndexOf('/') + 1, fullProperty.indexOf(".java"));
        return config + "-" + PROV_USAGE.name();
    }

    public static boolean isFirstProvider() {
        return Security.getProviders()[0].getName().equals("JipherJCE");
    }

    public static KeyStore getKeyStore(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KeyStore.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KeyStore.getInstance(alg, PROV_STRING);
            default -> KeyStore.getInstance(alg, instance);
        };
    }

    public static Object getKdf(String alg) throws Exception {
        Class<?> cls = Class.forName("javax.crypto.KDF");
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> cls.getMethod("getInstance", String.class).invoke(null, alg);
            case STRING, DYNAMIC_STRING ->
                    cls.getMethod("getInstance", String.class, String.class).invoke(null, alg, PROV_STRING);
            default -> cls.getMethod("getInstance", String.class, Provider.class).invoke(null, alg, instance);
        };
    }

    public static Object getKdf(String alg, Object kdfParameters) throws Exception {
        Class<?> cls = Class.forName("javax.crypto.KDF");
        Class<?> kdfParametersClass = Class.forName("javax.crypto.KDFParameters");
        try {
            return switch (PROV_USAGE) {
                case FIRST, DYNAMIC_FIRST ->
                        cls.getMethod("getInstance", String.class, kdfParametersClass).invoke(null, PROV_STRING, kdfParametersClass.cast(kdfParameters));
                case STRING, DYNAMIC_STRING ->
                        cls.getMethod("getInstance", String.class, kdfParametersClass, String.class).invoke(null, alg, kdfParametersClass.cast(kdfParameters), PROV_STRING);
                default ->
                        cls.getMethod("getInstance", String.class, kdfParametersClass, Provider.class).invoke(null, alg, kdfParametersClass.cast(kdfParameters), instance);
            };
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof InvalidAlgorithmParameterException) {
                throw (InvalidAlgorithmParameterException) e.getCause();
            }
            throw e;
        }
    }

    public static Mac getMac(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> Mac.getInstance(alg);
            case STRING, DYNAMIC_STRING -> Mac.getInstance(alg, PROV_STRING);
            default -> Mac.getInstance(alg, instance);
        };
    }

    public static MessageDigest getMessageDigest(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> MessageDigest.getInstance(alg);
            case DYNAMIC_STRING, STRING -> MessageDigest.getInstance(alg, PROV_STRING);
            default -> MessageDigest.getInstance(alg, instance);
        };
    }

    public static AlgorithmParameters getAlgorithmParameters(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> AlgorithmParameters.getInstance(alg);
            case STRING, DYNAMIC_STRING -> AlgorithmParameters.getInstance(alg, PROV_STRING);
            default -> AlgorithmParameters.getInstance(alg, instance);
        };
    }

    public static KeyAgreement getKeyAgreement(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KeyAgreement.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KeyAgreement.getInstance(alg, PROV_STRING);
            default -> KeyAgreement.getInstance(alg, instance);
        };
    }

    public static AlgorithmParameterGenerator getAlgorithmParameterGenerator(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> AlgorithmParameterGenerator.getInstance(alg);
            case STRING, DYNAMIC_STRING -> AlgorithmParameterGenerator.getInstance(alg, PROV_STRING);
            default -> AlgorithmParameterGenerator.getInstance(alg, instance);
        };
    }

    public static Cipher getCipher(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> Cipher.getInstance(alg);
            case STRING, DYNAMIC_STRING -> Cipher.getInstance(alg, PROV_STRING);
            default -> Cipher.getInstance(alg, instance);
        };
    }

    public static KEM getKEM(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KEM.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KEM.getInstance(alg, PROV_STRING);
            default -> KEM.getInstance(alg, instance);
        };
    }

    public static KeyFactory getKeyFactory(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KeyFactory.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KeyFactory.getInstance(alg, PROV_STRING);
            default -> KeyFactory.getInstance(alg, instance);
        };
    }

    public static KeyPairGenerator getKeyPairGenerator(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KeyPairGenerator.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KeyPairGenerator.getInstance(alg, PROV_STRING);
            default -> KeyPairGenerator.getInstance(alg, instance);
        };
    }

    public static Signature getSignature(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> Signature.getInstance(alg);
            case STRING, DYNAMIC_STRING -> Signature.getInstance(alg, PROV_STRING);
            default -> Signature.getInstance(alg, instance);
        };
    }

    public static SecretKeyFactory getSecretKeyFactory(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> SecretKeyFactory.getInstance(alg);
            case STRING, DYNAMIC_STRING -> SecretKeyFactory.getInstance(alg, PROV_STRING);
            default -> SecretKeyFactory.getInstance(alg, instance);
        };
    }

    public static SecureRandom getSecureRandom(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> SecureRandom.getInstance(alg);
            case STRING, DYNAMIC_STRING -> SecureRandom.getInstance(alg, PROV_STRING);
            default -> SecureRandom.getInstance(alg, instance);
        };
    }

    public static KeyGenerator getKeyGenerator(String alg) throws Exception {
        return switch (PROV_USAGE) {
            case FIRST, DYNAMIC_FIRST -> KeyGenerator.getInstance(alg);
            case STRING, DYNAMIC_STRING -> KeyGenerator.getInstance(alg, PROV_STRING);
            default -> KeyGenerator.getInstance(alg, instance);
        };
    }
}
