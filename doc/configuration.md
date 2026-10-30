# Configuration

Project Brisbane delivers its Java Security Provider in a Java module called `com.oracle.jipher`.

You can configure some of the features of Jipher through the Java system properties documented in the following sections.

## `java.security.debug`

Standard Java system property.

If the value includes `jipher` then debug logging through `System.err` is enabled within Jipher.

**Default value:** *None*

## `jipher.cipher.AEAD.stream`

Configures the streaming mode of AES/GCM Cipher objects.

When set to `false`, which is the default, ciphertext passed to each `Cipher.update` call is internally buffered.
The buffered ciphertext is later processed during the `Cipher.doFinal` call.
Authenticated recovered plaintext is returned if the AEAD tag is validated, otherwise an `AEADBadTagException` is thrown.

When set to `true`, ciphertext passed to each `Cipher.update` call is processed immediately to produce unauthenticated
recovered plaintext.
If the later `Cipher.doFinal` call fails to validate the AEAD tag then a `ProviderException` is thrown with the detail
message "Authentication tag does not match".
Applications should respond to this exception by discarding any unauthenticated recovered plaintext obtained
from earlier `Cipher.update` method calls.

## `jipher.fips.enforcement`

Specifies the FIPS 140 enforcement policy to be applied at the Java security provider layer.
It can have one of the following values:
* `FIPS`: Approved algorithms and key lengths are permitted in accordance with how they are used. Legacy use is permitted.
* `FIPS_STRICT`: Only algorithms and key lengths with Acceptable approval status are permitted.
* `NONE`: No additional enforcement is performed; any enforcement implemented in OpenSSL is still applied.
  This policy is intended to be used during preproduction debugging.
  You may encounter behavior that differs from the other policies such as:
    * A different exception being thrown
    * A delay in an exception being thrown; for example, an exception may be thrown when a signature object is used instead of when it is created or initialized

*Acceptable* is used by NIST to mean that the algorithm and key length is safe to use.

*Legacy use* means that the algorithm or key length may be used only to process already protected information,
for example, to decrypt ciphertext data or to verify a digital signature.
See [NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
for more information.

## `jipher.openssl.useOsInstance`

Configures Jipher to load the instance of the OpenSSL cryptographic library and FIPS provider managed by the operating system.

**Only** supported on Oracle Linux version 9.4 or later.

**Default value:** `false`

## `jipher.openssl.dir`

This system property is only active if `jipher.openssl.useOsInstance` is **not** set to `true`.

Specifies the path location that Jipher uses to load
the OpenSSL cryptographic library, FIPS provider and configuration file.

The directory must contain the following files:

| OS      | Files                                                                                                     |
|---------|-----------------------------------------------------------------------------------------------------------|
| Linux   | `lib/libcrypto.so.<major>` <br> `lib/ossl-modules/fips.so` <br> `ssl/fipsmodule.cnf` or `ssl/openssl.cnf`       |
| MacOS   | `lib/libcrypto.<major>.dylib` <br> `lib/ossl-modules/fips.dylib` <br> `ssl/fipsmodule.cnf` or `ssl/openssl.cnf` |
| Windows | `bin\libcrypto-<major>-x64.dll` <br> `lib\ossl-modules\fips.dll` <br> `ssl\fipsmodule.cnf` or `ssl\openssl.cnf` |

If `lib64` exists, it is preferred over `lib`.

**Default value:** *None*

If neither `jipher.openssl.useOsInstance` or `jipher.openssl.dir` are specified then Jipher will attempt
to load the OpenSSL cryptographic library, FIPS provider and configuration file from a platform specific location:

* *nix-like systems: `/opt/jipher/openssl`
* Windows: `C:\Program Files\jipher\openssl`

## `jipher.openssl.sanctioned.cryptoLibraryVersions`

This system property is only active if `jipher.openssl.useOsInstance` is **not** set to `true`.

If this system property is specified then Jipher will fail at start-up unless the version number
of the OpenSSL cryptography library it loads matches a version sanctioned by this system property value.
See [version sanctioning syntax](#Version-sanctioning-syntax) for more information.
If this system property is not set then Jipher will not check the version of the OpenSSL cryptography library it loads.

## `jipher.openssl.sanctioned.fipsProviderVersions`

This system property is only active if `jipher.openssl.useOsInstance` is **not** set to `true`.

If this system property is specified then Jipher will fail at start-up unless the version number
of the OpenSSL FIPS provider it loads matches a version sanctioned by this system property value.
See [version sanctioning syntax](#Version-sanctioning-syntax) for more information.
If this system property is not set then Jipher will not check the version of the OpenSSL FIPS provider it loads.

## `jipher.openssl.sanctioned.osProvided.cryptoLibraryVersions`

This system property is only active if `jipher.openssl.useOsInstance` is set to `true`.

If this system property is specified then Jipher will fail at start-up unless the version number
of the OpenSSL cryptography library it loads matches a version sanctioned by this system property value.
See [version sanctioning syntax](#Version-sanctioning-syntax) for more information.
If this system property is not set then Jipher will not check the version of the OpenSSL cryptography library it loads.

## `jipher.openssl.sanctioned.osProvided.fipsProviderVersions`

This system property is only active if `jipher.openssl.useOsInstance` is set to `true`.

If this system property is specified then Jipher will fail at start-up unless the version number
of the OpenSSL FIPS provider it loads matches a version sanctioned by this system property value.
See [version sanctioning syntax](#Version-sanctioning-syntax) for more information.
If this system property is not set then Jipher will not check the version of the OpenSSL FIPS provider it loads.

## `jipher.pbkdf2.minimumPasswordLength`

Specifies the minimum password length enforced for pbkdf2 operations. If unspecified it defaults to 8.

## Version sanctioning syntax

### Single version

A single version can be sanctioned by specifying its version.

For example, only version `3.5.4` is sanctioned:
```
3.5.4
```

### Version interval

Version ranges can be sanctioned by defining an optionally unbounded interval.
This is defined by its optional boundaries and the type of bracket used
to indicate whether those boundaries are included or excluded:
```
<open-bracket> <from-version> <comma> <to-version> <close-bracket>
```

Omitting `<from-version>` means unbounded below; omitting `<to-version>` means unbounded above.

Square brackets include the exact version:
* `[`: inclusive lower bound
* `]`: inclusive upper bound

Round brackets exclude the exact version:
* `(`: exclusive lower bound
* `)`: exclusive upper bound


Examples:
 * Versions after 3.5.1 and before 3.5.5 are sanctioned:
   ```
   (3.5.1,3.5.5)
   ```
 * Versions from 3.5.1 onward are sanctioned:
   ```
   [3.5.1,]
   ```
 * Versions before 3.6 are sanctioned:
   ```
   (,3.6)
   ```
 * Versions until 3.6 are sanctioned:
   ```
   (,3.6]
   ```

### Combining multiple individual versions and/or version intervals

You can combine multiple individual versions and/or version intervals using a comma as a separator
which acts as a logical OR (union). The union comma separates "items", where an item is either:
 * a single version, or
 * a bracketed interval.

Examples:
* Only versions 3.5.1 and 3.5.4 are sanctioned:
  ```
  3.5.1,3.5.4
  ```
* Version 3.5.1 and versions after 3.5.4 are sanctioned:
  ```
  3.5.1,(3.5.4,)
  ```
