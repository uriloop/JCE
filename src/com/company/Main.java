package com.company;

import com.company.utils.Cripto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {


        Cripto c= new Cripto();

        System.out.println("_____________________________");
        System.out.println("Exercici 1:");
        System.out.println("Generant keypair");
        KeyPair kp=c.randomGenerate(1024);

        System.out.println("Public key= "+kp.getPublic().getEncoded());
        System.out.println("Private key= "+kp.getPrivate().getEncoded());
        System.out.println("Public algorithm= "+kp.getPublic().getAlgorithm());
        System.out.println("Private algorithm= "+kp.getPrivate().getAlgorithm());
        System.out.println("Public format= "+kp.getPublic().getFormat());
        System.out.println("Private format= "+kp.getPrivate().getFormat());
        

        Scanner scanner= new Scanner(System.in);
        System.out.println("Introdueix un text a encriptar");
        String textAEncriptar=scanner.nextLine();


        // passem el string a array de bytes
        byte[] encriptat=c.encryptData(textAEncriptar.getBytes(),kp.getPublic());

        System.out.println("Aquest es el text encriptat: "+encriptat);

        byte[] textDesencriptat = c.decryptData(encriptat, kp.getPrivate());
        String resultat= null;

            resultat = new String(textDesencriptat);


        System.out.println("Aquest es el resultat de desencriptar el text amb la clau privada:");
        System.out.println(resultat);

        System.out.println("_____________________________");
        System.out.println("Exercici 2:");

        System.out.println("Carreguem la keystore amb nom 'keystore_oriol_lopez.ks' ");
        KeyStore ks= null;
        try {
            ks= c.loadKeyStore("../../../keystore_oriol.ks","password");

        } catch (Exception e) {
            e.printStackTrace();
        }



        System.out.println("Tipus keystore= "+ks.getType());

        try {

            System.out.println("Numero d'entrades a la keystore = "+ ks.size());

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }



        try {
            Enumeration<String> aliasGuardats = ks.aliases();
            System.out.println("Alias guardats: ");

            while (aliasGuardats.hasMoreElements()){
                String alias= aliasGuardats.nextElement();
                System.out.println("----------------------------------------------------");
                System.out.println("Alias= "+ alias);

            }
            aliasGuardats = ks.aliases();
            String alias= aliasGuardats.nextElement();
            System.out.println("----------------------------------------------------");
            System.out.println("Alias= "+ alias);
            Certificate cert = ks.getCertificate(alias);
            System.out.println("----------------------------------------------------");
            System.out.println("Certificat = "+ cert);
            System.out.println("----------------------------------------------------");
            System.out.println("Algoritme = "+ cert.getPublicKey().getAlgorithm());


        } catch (KeyStoreException e) {
            e.printStackTrace();
        }






        char[] pass = "password".toCharArray();

        KeyStore.SecretKeyEntry skEntry = null;
        try {
            skEntry = new KeyStore.SecretKeyEntry(c.generateSecretKey(256));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pass);
        try {
            ks.setEntry("novaClau", skEntry, protParam);
            FileOutputStream fos = new FileOutputStream("../../../keystore_oriol_lopez.ks");
            ks.store(fos,pass);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        System.out.println("---------------------------------");
        System.out.println("Exercici 3 ");

        PublicKey pk = c.getPublicKey("../../../uri.cert");
        System.out.println(" La clau publica del certificat 'uri.cert' és= "+pk.toString());

        // write your code here
        System.out.println("---------------------------------");
        System.out.println("Exercici 4");

        PublicKey pkey= null;
        try {
            pkey = c.getPublicKey(ks,"lamevaclau","password");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        System.out.println("La clau pública de la clau 'lamevaclau' desada a la keystore 'keystore_oriol_lopez.ks' és= \n"+pkey);



        System.out.println("---------------------------------");
        System.out.println("Exercici 5 ");

        System.out.println("Introdueix algun text per utilitzar com a dades que signarem digitalment amb la clau privada:");
        String dades = scanner.nextLine();

        byte[] signatura= c.signData(dades, kp.getPrivate());
        System.out.println("La signatura és "+signatura);




        System.out.println("---------------------------------");
        System.out.println("Exercici 6");

        boolean valid= c.validateSignature(dades,signatura, kp.getPublic());
        System.out.println("La validació retorna "+ valid);


        System.out.println("---------------------------------");
        System.out.println("Exercici 2.1");


        System.out.println("Introdueix un text a encriptar amb clau embolcallada:");
        String data= scanner.nextLine();

        byte[][] dataEncriptada= c.encryptWrappedData(data, kp.getPublic());

        System.out.println("El text encriptat és el següent:\n"+dataEncriptada.toString() );

        System.out.println("Desencriptem el text: ");

        byte[] decriptedData= new byte[0];

            decriptedData = c.decryptWrappedData(dataEncriptada,kp.getPrivate());


        String text= new String(decriptedData);

        System.out.println(text);






    }



}
