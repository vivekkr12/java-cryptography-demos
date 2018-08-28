package com.here.had.webapps.crypto;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;

public class EncryptionTest {

    @Test
    public void encryptDecryptAES() throws Exception{

        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256);
        // Generate the secret key specs.
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        String key = new String(Base64.getEncoder().encode(raw));

        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] bytes = cipher.doFinal("Hello World!".getBytes());
        String encrypted = new String(Base64.getEncoder().encode(bytes));

        System.out.println(encrypted);

        Cipher cipherDecrypt = Cipher.getInstance("AES");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decryptedBytes = cipherDecrypt.doFinal(bytes);
        String decryptedString = new String(decryptedBytes);

        System.out.println(decryptedString);
    }

    @Test
    public void asymmetricEncryptionDecryption() throws Exception{

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream is = this.getClass().getResourceAsStream("/vivek.pfx");
        keyStore.load(is, "password".toCharArray());

        PrivateKey priv = (PrivateKey) keyStore.getKey("vivek", "password".toCharArray());

        Cipher encrypt = Cipher.getInstance("RSA");
        encrypt.init(Cipher.ENCRYPT_MODE, priv);
        byte[] bytes = encrypt.doFinal("Hello World!".getBytes());

        String encrypted = new String(Base64.getEncoder().encode(bytes));

        System.out.println(encrypted);

        Cipher decrypt = Cipher.getInstance("RSA");
        decrypt.init(Cipher.DECRYPT_MODE, keyStore.getCertificate("vivek"));
        byte[] decryptedBytes = decrypt.doFinal(bytes);
        String decryptedString = new String(decryptedBytes);

        System.out.println(decryptedString);


    }

}
