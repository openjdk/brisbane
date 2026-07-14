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

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import static com.oracle.jipher.internal.openssl.RandUtil.runAdaptiveProportionTest;
import static com.oracle.jipher.internal.openssl.RandUtil.runRepetitionCountTest;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LibCtxTest {

    @Test
    public void getFipsProviderVersionString() throws Exception {
        String version = LibCtx.getFipsProviderVersionString();
        assertTrue(version.startsWith("3.") || version.equals("1.2.0"));
    }

    @Test
    public void forEachCipherTest() throws Exception {
        Set<String> names = new HashSet<>();
        LibCtx.forEachCipher(cipher -> cipher.forEachName(names::add));
        assertTrue(names.contains("aes-256-gcm"));
    }

    @Test
    public void forEachKdfTest() throws Exception {
        Set<String> names = new HashSet<>();
        LibCtx.forEachKdf(kdf -> kdf.forEachName(names::add));
        assertTrue(names.contains("PBKDF2"));
    }

    @Test
    public void forEachMacTest() throws Exception {
        Set<String> names = new HashSet<>();
        LibCtx.forEachMac(mac -> mac.forEachName(names::add));
        assertTrue(names.contains("HMAC"));
    }

    @Test
    public void forEachMdTest() throws Exception {
        Set<String> names = new HashSet<>();
        LibCtx.forEachMd(md -> md.forEachName(names::add));
        assertTrue(names.contains("SHA256"));
    }

    @Test
    public void forEachRandTest() throws Exception {
        Set<String> names = new HashSet<>();
        LibCtx.forEachRand(rand -> rand.forEachName(names::add));
        assertTrue(names.contains("CTR-DRBG"));
    }

    @Test
    public void newPkeyCtxTest() throws Exception {
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            EVP_PKEY_CTX ctx = LibCtx.newPkeyCtx("RSA", confinedArena);
            assertNotNull(ctx);
        }
    }

    @Test
    public void randBytesTest() {
        byte[] randomBytes = new byte[1000];
        LibCtx.randBytes(randomBytes, 256);

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }

    @Test
    public void randPrivBytesTest() {
        byte[] randomBytes = new byte[1000];
        LibCtx.randPrivBytes(randomBytes, 256);

        // Perform a sanity check on the random bytes.
        // Note this sanity check has a low but non-zero false positive probability.
        assertTrue(runRepetitionCountTest(randomBytes));
        assertTrue(runAdaptiveProportionTest(randomBytes));
    }
}
