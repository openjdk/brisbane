# Prerequisites

Project Brisbane delivers its Java Security Provider in a Java module called `com.oracle.jipher`.
This document lists prerequisites for building, testing, and using this module.

## OpenJDK

Brisbane is formally compatible with JDK 25 and later.

## Git

The source code is hosted on GitHub at [https://github.com/openjdk/brisbane](https://github.com/openjdk/brisbane).

Many (if not all) IDEs include built-in support.
For example, Eclipse uses EGit, which can be downloaded through the built-in update site
http://download.eclipse.org/releases/latest/ under Collaboration > Java implementation of Git.

For Linux, git can be installed via the software package manager.
On Windows, git can be downloaded from https://git-scm.com/install/windows.

## Gradle

Gradle is the primary build tool for building project Brisbane.
Since the repository includes a Gradle wrapper that will download the correct Gradle version when needed,
you do not need to manually install Gradle. The current and minimum Gradle version is 9.4.1.
If you want to generate a wrapper yourself (for example, you want to build the project with a different Gradle version),
then you will need to install Gradle.

The `sh gradlew` command used throughout this set of documents can be replaced with `gradle` when not using the wrapper.

### Toolchains

The Brisbane project uses [Gradle Java Toolchains](https://docs.gradle.org/current/userguide/toolchains.html#sec:java-toolchains).
It configures Gradle to use JDK 25 or later to compile and run the tests.
This can be different from the JDK used to *launch* Gradle.

How it works:
- If you launch Gradle with a JDK version higher than or equal to 25, then Gradle will use this version to compile
  and run the tests.
- If you launch Gradle with a JDK version lower than 25, then Gradle will try to locate a local JDK 25 installation.
    - See: [Auto-detection of installed toolchains](https://docs.gradle.org/current/userguide/toolchains.html#sec:auto_detection)
- If auto-provisioning is enabled, Gradle may download a matching JDK automatically.
    - See: [Auto-provisioning](https://docs.gradle.org/current/userguide/toolchains.html#sec:provisioning)

If auto-provisioning is disabled and Gradle cannot auto-detect a suitable local JDK, you can point Gradle at
a custom JDK install location using `org.gradle.java.installations.paths`.

This can be specified on the command line:
```
sh gradlew -Porg.gradle.java.installations.paths=/custom/path/to/jdk ...
```
or in a properties file, such as `~/.gradle/gradle.properties`:
```
org.gradle.java.installations.paths=/custom/path/to/jdk
```

## Environment Variables

 * `JAVA_HOME`

   Set `JAVA_HOME` to the root of a local JDK installation (the JDK used to *run Gradle*).
   * Example (macOS/Linux): `/usr/lib/jvm/jdk-25`
   * Example (Windows): `C:\Program Files\Java\jdk-25`

 * `PATH` (only if not using the Gradle Wrapper)

   Add `<gradle-x.y>/bin` to your `PATH`, where `x.y` is the Gradle version you installed.

   Note (Windows/Cygwin/MSYS): `JAVA_HOME` must be a Windows path (e.g., `C:\Program Files\...`),
   not a POSIX-style path like `/cygdrive/c/...`.

### How this interacts with Toolchains

`JAVA_HOME` is used only to locate a JVM to start Gradle (the Wrapper script runs Gradle using that JVM).
The Brisbane build uses Gradle Java Toolchains to compile and test with the project's minimum required JDK version.
See [Toolchains](#toolchains).

Test your settings with:
```
"$JAVA_HOME/bin/java" -version
sh gradlew -version
```

### Stopping Gradle daemons after environment changes

If you change environment variables (e.g., JAVA_HOME) or install/update a JDK/Gradle after a failed build,
stop any running Gradle daemons:

```
sh gradlew --stop
```

This is needed to ensure that the changes are observed by Gradle daemons that support the build
(by default Gradle starts a daemon that is used to speed up subsequent builds).
Additionally, on Windows platforms, the Gradle daemon can sometimes interfere with your ability to delete files that
it keeps open. If you run into problems you can stop the Gradle daemon with "`gradle --stop`"
(or disable the Gradle daemon altogether).

## OpenSSL

OpenSSL is **NOT** required to build Jipher. It is however required by Jipher at runtime.

At runtime Jipher loads the [OpenSSL](https://openssl-library.org/) cryptographic library, FIPS provider and
optionally (to access the FIPS module MAC) the OpenSSL configuration file from the filesystem.

Brisbane is compatible with any version of OpenSSL in which the major version is 3 or above.
The version of the OpenSSL cryptographic library does not need to match
the version of the OpenSSL FIPS provider.  For example, you could use
version 3.6.2 of the OpenSSL cryptographic library with version 3.5.4 of the OpenSSL FIPS provider.

### Using the instance provided by the operating system

Currently, this option is only supported on Oracle Linux version 9.4 or later.

Oracle Linux 9 and later provide an instance of the OpenSSL cryptographic library and FIPS provider.
They are usually pre-installed but if necessary they can be added via the package manager by installing the packages
`openssl-libs` and `openssl-fips-provider-so`.

To configure Jipher to use the OpenSSL instance provided by the operating system set the Java system property
`jipher.openssl.useOsInstance` to `true`.  For example:
```
java -Djipher.openssl.useOsInstance=true --module-path <path to jipher-jce JAR> -m com.oracle.jipher
```

Note: An OpenSSL configuration file containing the FIPS module MAC
is not required when using the OpenSSL instance provided by Oracle Linux
as the FIPS module MAC is embedded in the FIPS provider binary.

### Providing your own instance of OpenSSL

Source code for OpenSSL can be downloaded from https://openssl-library.org/source/.
Follow the documentation embedded in the OpenSSL source bundle, `INSTALL.md` and `README-FIPS.md`,
to build the OpenSSL cryptographic library and OpenSSL FIPS provider and to create an OpenSSL configuration file
containing the FIPS module MAC.

By default, Jipher loads the OpenSSL cryptographic library, FIPS provider and configuration file
from a platform specific location:

* *nix-like systems: `/opt/jipher/openssl`
* Windows: `C:\Program Files\jipher\openssl`

To configure Jipher to load the OpenSSL cryptographic library, FIPS provider and configuration file
from a custom location set the Java system property `jipher.openssl.dir` to specify the custom location.
For example,
```
java -Djipher.openssl.dir=<path to custom location> --module-path <path to jipher-jce JAR> -m com.oracle.jipher
```

The directory must contain:

| OS      | Files                                                                                                     |
|---------|-----------------------------------------------------------------------------------------------------------|
| Linux   | `lib/libcrypto.so.<major>` <br> `lib/ossl-modules/fips.so` <br> `ssl/fipsmodule.cnf` or `ssl/openssl.cnf`       |
| MacOS   | `lib/libcrypto.<major>.dylib` <br> `lib/ossl-modules/fips.dylib` <br> `ssl/fipsmodule.cnf` or `ssl/openssl.cnf` |
| Windows | `bin\libcrypto-<major>-x64.dll` <br> `lib\ossl-modules\fips.dll` <br> `ssl\fipsmodule.cnf` or `ssl\openssl.cnf` |

If `lib64` exists, it is preferred over `lib`.

### Using Gradle properties to configure how OpenSSL is located at runtime

Setting either of the Gradle properties:
* `jipher.openssl.useOsInstance`
* `jipher.openssl.dir`

configures Gradle to set a Java system property of the same name to the specified value whenever it creates
a JVM to test Jipher.  These Gradle properties can be set on the command line or in the Gradle properties file.
See [../gradle.properties](../gradle.properties).
