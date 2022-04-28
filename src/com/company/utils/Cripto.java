package com.company.utils;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Cripto {


    public KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public byte[] decryptData(byte[] data, PrivateKey priv) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, priv);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptedData;
    }

    public KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
       // KeyStore ks = KeyStore.getInstance("JCEKS");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        //KeyStore ks = KeyStore.getInstance("RSA");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public  SecretKey generateSecretKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public PublicKey getPublicKey(String fitxer){

        FileInputStream in = null;
        PublicKey pk = null;
        try {
            in = new FileInputStream(fitxer);

            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(in);
            pk = certificate.getPublicKey();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }


        return pk;

    }

    public PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws KeyStoreException {
        KeyStore keyStore = ks;

        char[] pass= pwMyKey.toCharArray();

        Key i= null;
        try {
            i = keyStore.getKey(alias, pass);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        if (i instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = ks.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            return publicKey;


        }
        return null;

    }


    public byte[] getSignature(String dades, PrivateKey pkey){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = md.digest(dades.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pkey);
            byte[] digitalSignature = cipher.doFinal(messageHash);

            System.out.println(digitalSignature.toString());
            return digitalSignature;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean validateSignature(String data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        byte[] data2= data.getBytes(StandardCharsets.UTF_8);
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data2);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }
}
