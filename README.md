# Cryptography with Java

This project contains samples on how to do cryptographic operations in Java using the [BouncyCastle](https://www.bouncycastle.org/) libray.

This is what you can expect to find the included classes:

1. [`ProvidersTest`](src/test/java/com/here/had/webapps/crypto/ProvidersTest.java): A demo of how JCE uses crypto providers and how external providers can be added
2. [`HashingTest`](src/test/java/com/here/had/webapps/crypto/HashingTest.java) : A demo of creating and validating crypto hash. Also includes an example of MD5 collision
3. [`EncryptionTest`](src/test/java/com/here/had/webapps/crypto/EncryptionTest.java) : Includes example of symmetrical and asymmetrical encruption and decryption
4. [`KeystoreAndKeysTest`](src/test/java/com/here/had/webapps/crypto/KeystoreAndKeysTest.java) : Demonstartes how crpto keys are generated and written into a keystore as well as accessed from different keystores. Includes samples of creating keystores, genrating X509 certificates and certificate chains, generating CSR and signing issued certificate with root certificate.
5. [`DigitalSignatureTest`](src/test/java/com/here/had/webapps/crypto/DigitalSignatureTest.java) : Shows how PKCS1 and PKCS7 digital signatures can be generated and verified.
