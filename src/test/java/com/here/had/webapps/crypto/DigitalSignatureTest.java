package com.here.had.webapps.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class DigitalSignatureTest {

    @Test
    public void pkcs1SignAndVerify() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256WithRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update("Hello World!".getBytes());
        byte[] signature = signer.sign();

        System.out.println(new String(Base64.getEncoder().encode(signature)));

        Signature verifier = Signature.getInstance("SHA256WithRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update("Hello World!".getBytes());
        boolean verify = verifier.verify(signature);
        System.out.println(verify);
    }


    @Test
    public void pkcs7SignAndVerify() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        InputStream is = this.getClass().getResourceAsStream("/vivek.pfx");
        keyStore.load(is, "password".toCharArray());

        Certificate certificate = keyStore.getCertificate("vivek");
        Key priv = keyStore.getKey("vivek", "password".toCharArray());

        Security.addProvider(new BouncyCastleProvider());

        Store certStore = new JcaCertStore(Arrays.asList(new Certificate[] { certificate }));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build((PrivateKey) priv);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, (X509Certificate)certificate));
        generator.addCertificates(certStore);
        CMSTypedData typedData = new CMSProcessableByteArray("Hello World!".getBytes());
        CMSSignedData signedData = generator.generate(typedData, true);
        System.out.println(new String(Base64.getEncoder().encode(signedData.getEncoded())));


        // Verification

        CMSSignedData cmsSignedData = new CMSSignedData(signedData.getEncoded());
        CMSProcessable cmsProcessable = cmsSignedData.getSignedContent();
        byte[] data = (byte[]) cmsProcessable.getContent();
        System.out.println("Data: " + new String(data));

        CollectionStore verifierCertStore = (CollectionStore) cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        SignerInformation signerInfo = (SignerInformation) signers.getSigners().iterator().next();
        X509CertificateHolder certHolder = (X509CertificateHolder) verifierCertStore.getMatches(signerInfo.getSID()).iterator().next();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bos = new ByteArrayInputStream(certHolder.getEncoded());
        X509Certificate publicKeyCert = (X509Certificate) factory.generateCertificate(bos);
        bos.close();

        boolean verified = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(publicKeyCert));
        System.out.println(verified);

    }
}
