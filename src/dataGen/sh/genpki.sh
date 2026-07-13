#!/bin/sh -e

#
# Copyright (c) 2026 Oracle and/or its affiliates.
#
# The Universal Permissive License (UPL), Version 1.0
#
# Subject to the condition set forth below, permission is hereby granted to any
# person obtaining a copy of this software, associated documentation and/or data
# (collectively the "Software"), free of charge and under any and all copyright
# rights in the Software, and any and all patent rights owned or freely
# licensable by each licensor hereunder covering either (i) the unmodified
# Software as contributed to or provided by such licensor, or (ii) the Larger
# Works (as defined below), to deal in both
#
# (a) the Software, and
#
# (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
# one is included with the Software (each a "Larger Work" to which the Software
# is contributed by such licensors),
#
# without restriction, including without limitation the rights to copy, create
# derivative works of, display, perform, and distribute the Software and make,
# use, sell, offer for sale, import, export, have made, and have sold the
# Software and the Larger Work(s), and to sublicense the foregoing rights on
# either these or other terms.
#
# This license is subject to the following condition:
#
# The above copyright notice and either this complete permission notice or at
# a minimum a reference to the UPL must be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

#
# Generate sample PKI for TLS testing
#
# The certificate hierarchy is as follows:
#
#   root -+-> clientca ---> client
#         |
#         +-> serverca -+-> rsa_server
#                       |
#                       +-> ec_p256_server
#                       |
#                       +-> ec_p384_server
#                       |
#                       +-> ec_p521_server
#                       |
#                       +-> dsa_server
#
# The clientca certificate is trusted by the server for client authentication.
# The serverca certificate is trusted by the client.
#
# The main products of this script are server.<ext>, client.<ext>,
# clienttrust.<ext> and servertrust.<ext>, where <ext> is jks or p12.
#
# The client.<ext> keystore contains the client end-entity certificate and
# private key along with the clientca and root certificates.
#
# The server.<ext> keystore contains the server end-entity certificates
# (rsa_server, ec_p256_server, ec_p384_server, ec_p521_server and dsa_server)
# and their corresponding private keys along with the serverca and root
# certificates.
#
# The clienttrust.<ext> keystore contains the serverca certificate while the
# servertrust.<ext> keystore contains the clientca certificate.
#

# Determine how to run keytool (and java & javac)
if [ -n "$JAVA_HOME" ] ; then
    KEYTOOL_CMD="$JAVA_HOME/bin/keytool"
    JAVA_CMD="$JAVA_HOME/bin/java"
    JAVAC_CMD="$JAVA_HOME/bin/javac"
else
    KEYTOOL_CMD=keytool
    JAVA_CMD=java
    JAVAC_CMD=javac
fi
if ! command -v  "$KEYTOOL_CMD" >/dev/null 2>&1 ; then
   echo "Failed to run java keytool." >&2
   echo "   Check your PATH or JAVA_HOME environment variable settings facilitate running java keytool" >&2
   exit 1
fi

# Check that the Java version supports RFC 9879. At the time of writing this was JDK 26+
# (Sanitize version number to allow for early access releases)
KEYTOOL_JAVA_MAJOR_VERSION=$($KEYTOOL_CMD -J-version 2>&1 | awk -F'[".]' '/version/ {print $2}' | sed 's/[^0-9].*//')
echo "Current keytool java runtime major version: $KEYTOOL_JAVA_MAJOR_VERSION."
if [ "$KEYTOOL_JAVA_MAJOR_VERSION" -lt '26' ]; then
    echo "The keytool java runtime version must support RFC 9879."
    echo "Please rerun this script with PATH or JAVA_HOME set to use a java keytool with java runtime version 26 or later."
    exit 1
fi

mkdir -p build/generated/pki
cd build/generated/pki

# Configure keytool to create FIPS compliant pkcs12 keystores - see RFC 9879
KEYTOOL_CMD="$KEYTOOL_CMD -J-Dkeystore.pkcs12.keyProtectionAlgorithm=PBEWithHmacSHA256andAES_256"
KEYTOOL_CMD="$KEYTOOL_CMD -J-Dkeystore.pkcs12.certProtectionAlgorithm=PBEWithHmacSHA256andAES_256"
KEYTOOL_CMD="$KEYTOOL_CMD -J-Dkeystore.pkcs12.macAlgorithm=PBEWithHmacSHA256"

serverip=127.0.0.1
pass=Password1
validity=$((365 * 5)) # 5 years

# Set the root and intermediate CA certificate key algorithms
# RSA, DSA or EC
root_keyalg=RSA
ca_keyalg=RSA

# Set the client end-entity key algorithm and Key Usage
client_ee_keyalg=RSA
client_eeku=digitalSignature

# Set the store type
#ext=jks
#st=jks
ext=p12
st=pkcs12

rm -f root.pem serverca.pem clientca.pem client.pem
rm -f rsa_server.pem ec_p256_server.pem ec_p384_server.pem ec_p521_server.pem dsa_server.pem
rm -f root.$ext serverca.$ext server.$ext clientca.$ext client.$ext
rm -f clienttrust.$ext servertrust.$ext genpki_log.txt

echo "Certificate validity: $validity days"

#
# Get the default key generation parameters to use for the given key type.
# Sets the keyparam shell variable.
#
# Usage: get_keyparam <1:keyalg>
#
get_keyparam()
{
    case $1 in
    rsa|RSA|dsa|DSA)
        keyparam="-keysize 2048" ;;
    ec|EC)
        keyparam="-keysize 256" ;;
    esac
}

#
# Get the default signature algorithm to use for the given key type.
# Sets the sigalg shell variable.
#
# Usage: get_sigalg <1:keyalg>
#
get_sigalg()
{
    case $1 in
    rsa|RSA)
        sigalg="SHA256withRSA" ;;
    dsa|DSA)
        sigalg="SHA256withDSA" ;;
    ec|EC)
        sigalg="SHA256withECDSA" ;;
    esac
}

#
# Generate a key-pair.
#
# Usage: gen_keypair <1:alias> <2:keyalg> <3:certext> <4:dname> <5:keystore>
#
gen_keypair()
{
    echo "Generating $2 key-pair for $1"
    get_keyparam "$2"
    get_sigalg "$2"
    $KEYTOOL_CMD -keypass $pass -storepass $pass -genkeypair -keyalg "$2" $keyparam \
        -sigalg "$sigalg" -storetype $st -keystore "$5" -alias "$1" $3              \
        -validity $validity -dname "$4" 2>> genpki_log.txt
}

#
# Generate an EC key-pair for a specific named curve.
#
# Usage: gen_ec_keypair <1:alias> <2:groupname> <3:certext> <4:dname> <5:keystore>
#
gen_ec_keypair()
{
    echo "Generating EC key-pair for $1 using $2"
    get_sigalg EC
    $KEYTOOL_CMD -keypass $pass -storepass $pass -genkeypair -keyalg EC                 \
        -groupname "$2" -sigalg "$sigalg" -storetype $st -keystore "$5" -alias "$1" $3  \
        -validity $validity -dname "$4" 2>> genpki_log.txt
}

#
# Import a certificate into the specified keystore.
#
# Usage: import_cert <1:alias> <2:pem> <3:keystore>
#
import_cert()
{
    echo "Importing $2 into $3 as $1"
    $KEYTOOL_CMD -storepass $pass -storetype $st -keystore "$3" -importcert       \
        -alias "$1" -file "$2" -noprompt 2>> genpki_log.txt
}

#
# Generate a certificate for the specified key-pair and replace the self-signed
# placeholder certificate with the generated certificate.
#
# Usage: gen_cert <1:alias> <2:keyalg> <3:signer_alias> <4:signer_keyalg>
#                <5:certext> <6:certs> <7:keystore>
#
gen_cert()
{
    get_sigalg "$4"
    signer_sigalg=$sigalg
    get_sigalg "$2"
    echo "Issuing certificate for $1 signed by $3 using $signer_sigalg"
    $KEYTOOL_CMD -keypass $pass -storepass $pass -storetype $st -keystore "$7"    \
        -certreq -sigalg "$sigalg" -alias "$1" |
            $KEYTOOL_CMD $SECURITY_PROPERTIES_CLAUSE                              \
                -keypass $pass -storepass $pass -storetype $st                    \
                -keystore "$3.$ext" -gencert -sigalg "$signer_sigalg"             \
                -validity $validity -alias "$3" $5 -rfc > "$1.pem"

# Import the issued certificate into the keystore, replacing the self-signed
# placeholder certificate, along with the rest of the certificate chain
    echo "Importing certs ($6 $1.pem) into $7"
    cat $6 "$1.pem" |
        $KEYTOOL_CMD -storepass $pass -storetype $st -keystore "$7"               \
            -importcert -alias "$1" -noprompt 2>> genpki_log.txt
}

#
# Generate a key-pair and issue a new certificate signed by the specified
# signer.
#
# Usage: issue_cert <1:alias> <2:keyalg> <3:signer_alias> <4:signer_keyalg>
#                  <5:genkey_certext> <6:dname> <7:gencert_certext> <8:certs>
#                  <9:keystore>
#
issue_cert()
{
    gen_keypair "$1" "$2" "$5" "$6" "$9"
    gen_cert "$1" "$2" "$3" "$4" "$7" "$8" "$9"
}

#
# Generate an EC key-pair for a specific named curve and issue a new certificate
# signed by the specified signer.
#
# Usage: issue_ec_cert <1:alias> <2:groupname> <3:signer_alias> <4:signer_keyalg>
#                     <5:genkey_certext> <6:dname> <7:gencert_certext> <8:certs>
#                     <9:keystore>
#
issue_ec_cert()
{
    gen_ec_keypair "$1" "$2" "$5" "$6" "$9"
    gen_cert "$1" EC "$3" "$4" "$7" "$8" "$9"
}

# Generate key-pair for root certificate
echo "Generating root key-pair"
gen_keypair root $root_keyalg "-ext bc:c" "OU=Root Certificate Authority, O=BigCA, L=Cupertino, ST=CA, C=US" root.$ext

# Export the self-signed root certificate
echo "Exporting root cert"
$KEYTOOL_CMD -storepass $pass -storetype $st -keystore root.$ext -alias root      \
    -exportcert -rfc > root.pem

echo "*** Issuing certificates"

# Issue intermediate CA certificate (server-CA)
issue_cert serverca $ca_keyalg root $root_keyalg "-ext bc:c"                       \
    "OU=Certificate Authority 1, O=BigCA, L=Cupertino, ST=CA, C=US"               \
    "-ext BC=0" root.pem serverca.$ext

# Issue RSA end entity certificate (server-EE)
eeku=digitalSignature,keyEncipherment
issue_cert rsa_server RSA serverca $ca_keyalg ""                                   \
    "CN=$serverip, OU=Widget Development Group, O=Ficticious Widgets\\, Inc., L=San Mateo, ST=CA, C=US" \
    "-ext KU:c=$eeku -ext SAN=IP:$serverip" "root.pem serverca.pem" server.$ext

# Issue EC end entity certificate (server-EE)
eeku=digitalSignature,keyAgreement
issue_ec_cert ec_p256_server secp256r1 serverca $ca_keyalg ""                     \
    "CN=$serverip, OU=Widget Development Group, O=Ficticious Widgets\\, Inc., L=San Mateo, ST=CA, C=US" \
    "-ext KU:c=$eeku -ext SAN=IP:$serverip" "root.pem serverca.pem" server.$ext
issue_ec_cert ec_p384_server secp384r1 serverca $ca_keyalg ""                     \
    "CN=$serverip, OU=Widget Development Group, O=Ficticious Widgets\\, Inc., L=San Mateo, ST=CA, C=US" \
    "-ext KU:c=$eeku -ext SAN=IP:$serverip" "root.pem serverca.pem" server.$ext
issue_ec_cert ec_p521_server secp521r1 serverca $ca_keyalg ""                     \
    "CN=$serverip, OU=Widget Development Group, O=Ficticious Widgets\\, Inc., L=San Mateo, ST=CA, C=US" \
    "-ext KU:c=$eeku -ext SAN=IP:$serverip" "root.pem serverca.pem" server.$ext

# Issue DSA end entity certificate (server-EE)
eeku=digitalSignature
issue_cert dsa_server DSA serverca $ca_keyalg ""                                   \
    "CN=$serverip, OU=Widget Development Group, O=Ficticious Widgets\\, Inc., L=San Mateo, ST=CA, C=US" \
    "-ext KU:c=$eeku -ext SAN=IP:$serverip" "root.pem serverca.pem" server.$ext

# Issue intermediate CA certificate (client-CA)
issue_cert clientca $ca_keyalg root $root_keyalg "-ext bc:c"                       \
    "OU=Certificate Authority 2, O=BigCA, L=Cupertino, ST=CA, C=US"               \
    "-ext BC=0" root.pem clientca.$ext

# Issue end entity certificate for client authentication (client-EE)
issue_cert client $client_ee_keyalg clientca $ca_keyalg ""                         \
    "CN=Duke, OU=Java Software, O=Oracle, L=Cupertino, ST=CA, C=US"               \
    "-ext KU:c=$client_eeku" "root.pem clientca.pem" client.$ext

echo "*** Creating trust stores"

# Create a trust store for the server that contains the client CA certificate
import_cert clientca clientca.pem servertrust.$ext
# Create a trust store for the client that contains the server CA certificate
import_cert serverca serverca.pem clienttrust.$ext

# Workaround for the absence of PKCS#12 KeyStore support for RFC 9879 in JDK versions less than 26 - See JDK-8343232
# This can be removed when support for RFC 9879 is backported to JDK 25
echo "*** Creating a copy of each keystore with keystore.pkcs12.macAlgorithm set to NONE"

# Create a java utility that sets a PKCS12 keystore mac algorithm to NONE
cat > MacAlgNoneUtil.java <<MAC_ALG_NON_UTIL_DELIMITER
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.KeyStore;
import java.security.Security;

import java.util.Enumeration;

public final class MacAlgNoneUtil {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: MacAlgUtil <input keystore> <output keystore>, <password>");
            System.exit(1);
        }
        String inFilename = args[0];
        String outFilename = args[1];
        char[] password = args[2].toCharArray();

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);

        Security.setProperty("keystore.pkcs12.macAlgorithm", "NONE");

        KeyStore inKeyStore  = KeyStore.getInstance("PKCS12");
        KeyStore outKeyStore = KeyStore.getInstance("PKCS12");

        InputStream in = new FileInputStream(inFilename);
        inKeyStore.load(in, password);
        in.close();

        outKeyStore.load(null, null);

        Enumeration<String> es = inKeyStore.aliases();
        while (es.hasMoreElements()) {
            String alias = es.nextElement();
            try {
                KeyStore.Entry entry = inKeyStore.getEntry(alias, protectionParameter);
                outKeyStore.setEntry(alias, entry, protectionParameter);
            } catch (java.lang.UnsupportedOperationException e) {
                // Trusted certificate entries are not password-protected
                KeyStore.Entry entry = inKeyStore.getEntry(alias, null);
                outKeyStore.setEntry(alias, entry, null);
            }
        }

        OutputStream out = new FileOutputStream(outFilename);
        outKeyStore.store(out, password);
        out.close();
    }
}
MAC_ALG_NON_UTIL_DELIMITER

# Compile the java utility that sets a PKCS12 keystore mac algorithm to NONE
"$JAVAC_CMD" MacAlgNoneUtil.java

mkdir -p nomac

# Creating a copy of each keystore with keystore.pkcs12.macAlgorithm set to NONE
for keystore in *.p12; do
   echo "${keystore}"
   "$JAVA_CMD" MacAlgNoneUtil "${keystore}" "nomac/${keystore}" $pass
done

rm -f MacAlgNoneUtil.java MacAlgNoneUtil.class
