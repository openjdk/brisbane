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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class DebugTest {

    static final String MESSAGE = "Expected Message";

    @Test
    public void isEnabledTest() throws Exception {
        try (MockedStatic<ToolkitProperties> MockToolkitProperties = Mockito.mockStatic(ToolkitProperties.class)) {
            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn(null);
            Assert.assertFalse(Debug.isEnabled("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("other");
            Assert.assertFalse(Debug.isEnabled("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("jipher");
            Assert.assertTrue(Debug.isEnabled("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("all");
            Assert.assertTrue(Debug.isEnabled("jipher"));
        }
    }

    @Test
    public void getInstanceTest() throws Exception {
        Debug debug;

        try (MockedStatic<ToolkitProperties> MockToolkitProperties = Mockito.mockStatic(ToolkitProperties.class)) {
            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn(null);
            assertEquals(Debug.NONE, Debug.getInstance("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("other");
            assertEquals(Debug.NONE, Debug.getInstance("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("jipher");
            assertNotEquals(Debug.NONE, Debug.getInstance("jipher"));

            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("all");
            assertNotEquals(Debug.NONE, Debug.getInstance("jipher"));
        }
    }

    @Test
    public void printlnTest() throws Exception {
        // Save origin system error stream
        PrintStream originalSystemErr = System.err;

        // Redirect System.err to a byte array.
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));

        // Test outputting a message
        try (MockedStatic<ToolkitProperties> MockToolkitProperties = Mockito.mockStatic(ToolkitProperties.class)) {
            MockToolkitProperties.when(ToolkitProperties::getJavaSecurityDebugValue).thenReturn("jipher");
            Debug.getInstance("jipher").println(() -> MESSAGE);
            Assert.assertTrue(errContent.toString().contains("jipher: " + MESSAGE));
        }

        // Restore original  system error stream
        System.setErr(originalSystemErr);
    }
}
