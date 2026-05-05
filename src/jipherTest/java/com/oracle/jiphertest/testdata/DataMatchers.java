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

package com.oracle.jiphertest.testdata;

public class DataMatchers {

    public static TestDataMatcher alg(String alg) {
        return new Simple(alg);
    }

    public static TestDataMatcher secParam(String secParam) {
        return new Simple().secParam(secParam);
    }

    public static TestDataMatcher keyId(final String id) {
        return new Simple().keyId(id);
    }

    public static SymCipherMatcher symMatcher() {
        return new SymCipherMatcher();
    }

    public static PssParamMatcher pssMatcher() {
        return new PssParamMatcher();
    }
    public static class SymCipherMatcher extends Simple {

        private int keySize = -1;
        private DataSize aadSize;
        private int blockAlignedSize = -1;
        private int blockUnalignedSize = -1;

        public SymCipherMatcher keySize(int size) {
            this.keySize = size;
            return this;
        }

        public SymCipherMatcher alg(String alg) {
            this.alg = alg;
            return this;
        }

        public SymCipherMatcher dataMin(int len) {
            this.dataMinLen = len;
            return this;
        }

        public SymCipherMatcher dataSize(DataSize size) {
            this.dataSize = size;
            return this;
        }
        public SymCipherMatcher aad(DataSize size) {
            this.aadSize = size;
            return this;
        }
        public SymCipherMatcher blockAligned(int blockSize) {
            this.blockAlignedSize = blockSize;
            return this;
        }
        public SymCipherMatcher blockUnaligned(int blockSize) {
            this.blockUnalignedSize = blockSize;
            return this;
        }

        @Override
        public boolean matches(TestDataItem item) {
            if (!(item instanceof SymCipherTestVector tv)) {
                throw new Error("SymCipherMatcher can only be used with SymCipherTestVector");
            }
            if (!super.matches(item)) {
                return false;
            }
            if (keySize != -1 && tv.getKey().length != keySize) {
                return false;
            }
            if (blockAlignedSize != -1 && tv.getData().length != 0 && (tv.getData().length % blockAlignedSize) != 0) {
                return false;
            }
            if (blockUnalignedSize != -1 && tv.getData().length != 0 && (tv.getData().length % blockUnalignedSize) == 0) {
                return false;
            }
            if (this.aadSize != null) {
                int length = tv.getAadLen();
                if (this.aadSize == DataSize.EMPTY) {
                    if (length != 0) {
                        return false;
                    }
                } else if (this.aadSize == DataSize.BASIC) {
                    if (length == 0 || length >= 1000) {
                        return false;
                    }
                } else if (this.aadSize == DataSize.LARGE) {
                    if (length < 1000) {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    public static class PssParamMatcher extends Simple {
        private String digestAlg;
        public PssParamMatcher digest(String digestAlg) {
            this.digestAlg = digestAlg;
            return this;
        }
        public PssParamMatcher alg(String alg) {
            this.alg = alg;
            return this;
        }


        @Override
        public boolean matches(TestDataItem item) {
            if (!(item instanceof SignatureTestVector tv)) {
                throw new Error("PssParamMatcher can only be used with SignatureTestVector");
            }
            if (!super.matches(item)) {
                return false;
            }
            return this.digestAlg.equals(tv.getParams().digest());
        }
    }

    public static class Simple implements TestDataMatcher {
        String alg;
        DataSize dataSize;
        int dataMinLen = -1;
        private String secParam;
        private String prov;
        private String keyId;

        Simple() {
            // DO nothing.
        }

        Simple(String alg) {
            this.alg = alg;
        }

        @Override
        public TestDataMatcher dataSize(DataSize size) {
            this.dataSize = size;
            return this;
        }
        @Override
        public TestDataMatcher keyId(String id) {
            this.keyId = id;
            return this;
        }
        @Override
        public TestDataMatcher secParam(String secParam) {
            this.secParam = secParam;
            return this;
        }
        @Override
        public TestDataMatcher prov(String prov) {
            this.prov = prov;
            return this;
        }

        @Override
        public boolean matches(TestDataItem item) {
            if (this.alg != null && !this.alg.equals(item.getAlg())) {
                return false;
            }
            if (this.dataSize != null && this.dataSize != item.getDataSize()) {
                return false;
            }
            if (this.dataMinLen != -1 && item.getData().length < this.dataMinLen) {
                return false;
            }
            if (this.secParam != null && !item.getSecParam().equals(this.secParam)) {
                return false;
            }
            if (this.prov != null && !item.getProvider().equals(this.prov)) {
                return false;
            }
            if (this.keyId != null && !item.getKeyId().equals(this.keyId)) {
                return false;
            }
            return true;
        }

        @Override
        public String toString() {
            return "SimpleTestDataMatcher [alg=" + alg + ", dataSize=" + dataSize + ", secParam=" + secParam
                    + ", prov=" + prov + "]";
        }
    }
}
