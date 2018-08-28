package com.here.had.webapps.crypto;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashingTest {

    private String data = "The Future of Map Making is HERE";

    @Test
    public void testMd5HashCalculation() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] digest = messageDigest.digest(data.getBytes());
        System.out.println(new String(Base64.getEncoder().encode(digest)));
    }

    @Test
    public void testMd5HashChangedAfterDataChange() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] digest = messageDigest.digest(data.replace('E', 'F').getBytes());
        System.out.println(new String(Base64.getEncoder().encode(digest)));
    }

    @Test
    public void testSha1HashCalculation() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
        byte[] digest = messageDigest.digest(data.getBytes());
        System.out.println(new String(Base64.getEncoder().encode(digest)));
    }

    @Test
    public void testMd5HashCollision() throws NoSuchAlgorithmException {
        // Example from here - https://crypto.stackexchange.com/a/15889
        byte[] data1 = DatatypeConverter.parseHexBinary("4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2");
        byte[] data2 = DatatypeConverter.parseHexBinary("4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2");


        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] digest1 = messageDigest.digest(data1);
        byte[] digest2 = messageDigest.digest(data2);
        System.out.println(new String(Base64.getEncoder().encode(digest1)));
        System.out.println(new String(Base64.getEncoder().encode(digest2)));

        System.out.println(new String(Base64.getEncoder().encode(digest1)).equals(new String(Base64.getEncoder().encode(digest2))));

    }
}
