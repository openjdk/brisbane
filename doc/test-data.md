# Test Data

This document explains where the Jipher test vectors are stored, how to load them via the test helper APIs,
and how to regenerate the TLS PKI assets.

## Algorithm Test Vectors

Test Data for algorithm test vectors are stored in JSON format in `src/jipherTest/resources/com/oracle/jiphertest/testdata`

Test Data Java Objects are in the `jipherTest` sourceset: `com.oracle.jiphertest.testdata`

## Accessing Test Vector Data In Test Code

The `com.oracle.jiphertest.TestData` class can be used to retrieve test vectors.

Use `forParameterized` method to retrieve the collection of test vectors for a test vector type
in a format friendly for @Parameterized junit testing

```
@Parameterized.Parameters(name = "{index}: {0}")
public static Collection<Object[]> data() throws Exception {
    return TestData.forParameterized(AsymCipherTestVector.class);
}
```

Use `getFirst` method to retrieve the first test vector matching the specified criteria, via a `TestDataMatcher`.

```
import static com.oracle.jiphertest.testdata.DataMatchers.alg;
...

// Match by algorithm
DigestTestVector tv = TestData.getFirst(DigestTestVector.class, alg("SHA-256"));

// Match by algorithm and data size
DigestTestVector tv = TestData.getFirst(DigestTestVector.class, alg("SHA-256").dataSize(DataSize.EMPTY));

// Match by algorithm and security parameter
KeyPairTestData kpData = TestData.getFirst(KeyPairTestData.class, alg("RSA").secParam("2048"));
KeyPairTestData kpData = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
```

Use `get` method to retrieve the collection of test vectors matching the specified criteria, via a `TestDataMatcher`.
```
import static com.oracle.jiphertest.testdata.DataMatchers.alg;
...

// Match by algorithm and security parameter.
List<KeyPairTestData> kps = TestData.get(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
```

See `com.oracle.jiphertest.testdata.DataMatchers` for more matching criteria.

## Generation Of PKI For The TLS Tests

The shell script `src/dataGen/sh/genpki.sh` is used to generate PKI for the TLS tests.
All output files are placed in `build/generated/pki`.

```
> src/dataGen/sh/genpki.sh
```

After running the command
 * the `server.p12`, `client.p12`, `clienttrust.p12` and `servertrust.p12` files
   must be copied to the `src/jipherTest/resources/pki` directory

and
 * the `nomac/server.p12`, `nomac/client.p12`, `nomac/clienttrust.p12` and `nomac/servertrust.p12` files
   must be copied to the `src/jipherTest/resources/pki/nomac` directory

to be picked up by the tests.

The generated PKI certificate hierarchy is as follows:
```
  root -+-> clientca ---> client
        |
        +-> serverca -+-> rsa_server
                      |
                      +-> ec_p256_server
                      |
                      +-> ec_p384_server
                      |
                      +-> ec_p521_server
                      |
                      +-> dsa_server
```

The **clientca** certificate is trusted by the server for client authentication.
The **serverca** certificate is trusted by the client.

The `client.p12` keystore contains the client end-entity certificate and
private key along with the **clientca** and **root** certificates.

The `server.p12` keystore contains the server end-entity certificates
(**rsa_server**, **ec_p256_server**, **ec_p384_server**, **ec_p521_server** and
**dsa_server**) and their corresponding private keys along with the **serverca**
and **root** certificates.

The `clienttrust.p12` keystore contains the **serverca** certificate while the
`servertrust.p12` keystore contains the **clientca** certificate.

## Generation Of PKI For RFC 9579 Keystore Test

The `.p12` files in [src/jipherTest/resources/keystore](../src/jipherTest/resources/keystore) were generated
using the script [src/jipherTest/resources/keystore/generateRfc9579PKCS12Keystore.sh](../src/jipherTest/resources/keystore/generateRfc9579PKCS12Keystore.sh).

The script uses OpenJDK 26 and the OpenSSL command line utility to generate PKCS12 keystores that only employ
FIPS allowed cryptography.
