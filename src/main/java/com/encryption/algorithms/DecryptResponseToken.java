package com.encryption.algorithms;

import java.io.IOException;

import java.nio.charset.StandardCharsets;

import java.security.*;

import java.security.spec.*;

import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;

import java.nio.file.Files;

import java.nio.file.Paths;

import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;

import java.security.PrivateKey;

import java.security.spec.InvalidKeySpecException;

import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Base64;

public class DecryptResponseToken{

    //working
//
//    public static void main(String[] args) {
//        try {
//
//            PrivateKey privateKey = loadPrivateKey("D:\\New folder\\private_key.pem");
//
//            PublicKey publicKey = loadPublicKey("D:\\New folder\\public_key.pem");
//
//            // Step 2: Generate AES key (for encrypting the large data)
//            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
//            aesKeyGen.init(256); // AES-256 key
//            SecretKey aesKey = aesKeyGen.generateKey();
//
//
//            // Step 3: Encrypt the large data using AES
//            String largeData = "{\n" +
//                    "  iss: 'CVS-AVScan',\n" +
//                    "  aud: 'Next-Gen-Scheduling',\n" +
//                    "  iat: 1725903517,\n" +
//                    "  exp: 1725907117,\n" +
//                    "  jti: '0gYs6MY3Ry3Rk1PCXasqoDuv0xEFDsZG',\n" +
//                    "  cvs_status_code: '0000',\n" +
//                    "  cvs_status_desc: 'Success',\n" +
//                    "  cvs_av_original_file_name: 'screenshot',\n" +
//                    "  cvs_av_original_file_type: 'jpg',\n" +
//                    "  cvs_av_is_file_clean: 'y',\n" +
//                    "  cvs_av_file_ref: '1725903517941-screenshot-b9d5afba',\n" +
//                    "  cvs_av_file_download_key: '2Yd7bQPSUQgoKZ90StzhGe634IY0ovWX',\n" +
//                    "  cvs_av_client_state: 'teststate'\n" +
//                    "}";
//            String encryptedData = encryptWithAES(largeData, aesKey);
//
//            // Step 4: Encrypt the AES key using RSA
//            String encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);
//
//            // Now you have the encrypted data and the encrypted AES key
//            System.out.println("Encrypted Data: " + encryptedData);
//            System.out.println("Encrypted AES Key: " + encryptedAESKey);
//
//            // Step 5: Decrypt the AES key using RSA
//            SecretKey decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, privateKey);
//
//            // Step 6: Decrypt the large data using the decrypted AES key
//            String decryptedData = decryptWithAES(encryptedData, decryptedAESKey);
//            System.out.println("Decrypted Data: " + decryptedData);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    public static PublicKey loadPublicKey(String publicKeyPath) throws Exception {
//        String key = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
//        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
//                .replace("-----END PUBLIC KEY-----", "")
//                .replaceAll("\\s", "");
//        byte[] decodedKey = Base64.getDecoder().decode(key);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePublic(spec);
//    }
//
//    public static PrivateKey loadPrivateKey(String privateKeyPath) throws Exception {
//        String key = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
//        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
//                .replace("-----END PRIVATE KEY-----", "")
//                .replaceAll("\\s", "");
//        byte[] decodedKey = Base64.getDecoder().decode(key);
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePrivate(spec);
//    }
//
//
//    // AES encryption
//    public static String encryptWithAES(String plainText, SecretKey aesKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("AES");
//        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
//        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
//        return Base64.getEncoder().encodeToString(encryptedBytes);
//    }
//
//    // AES decryption
//    public static String decryptWithAES(String encryptedText, SecretKey aesKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("AES");
//        cipher.init(Cipher.DECRYPT_MODE, aesKey);
//        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
//        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
//        return new String(decryptedBytes);
//    }
//
//    // RSA encryption for AES key
//    public static String encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
//        return Base64.getEncoder().encodeToString(encryptedKey);
//    }
//
//    // RSA decryption for AES key
//    public static SecretKey decryptAESKeyWithRSA(String encryptedAESKey, PrivateKey privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decodedKey = Base64.getDecoder().decode(encryptedAESKey);
//        byte[] decryptedKey = cipher.doFinal(decodedKey);
//        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
//    }
//









    //code 1

    public static SecurityKeys createPublicAndPrivateKeys()  {

        // Generate public and private key
        SecurityKeys SecurityKeys = new SecurityKeys();
        String publicKeyValue = null;
        PublicKey publicKey = null;
        //long keyExpire = 600;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            SecurityKeys.setPrivateKey1(privateKey);
            Base64.Encoder encoder = Base64.getEncoder();
            SecurityKeys.setPublicKey(encoder.encodeToString(publicKey.getEncoded()));
            SecurityKeys.setPrivateKey(encoder.encodeToString(privateKey.getEncoded()));
            publicKeyValue = encoder.encodeToString(publicKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return SecurityKeys;
    }

    public static String encryptWithRSA(String plainText,String publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static PublicKey getPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static String decryptWithRSA(String encryptedText, PrivateKey privateKey) throws Exception {
        try{
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }catch (Exception e){
            e.printStackTrace();
        }

        return encryptedText;
    }

    public static void main(String[] args) {
        try {
            SecurityKeys publicAndPrivateKeys = createPublicAndPrivateKeys();
            System.out.println(publicAndPrivateKeys.getPrivateKey());
            System.out.println(publicAndPrivateKeys.getPublicKey());
            System.out.println(publicAndPrivateKeys.getEncryptedData());

            String payLoad = "{\n" +
                    "  iss: 'CVS-AVScan',\n" +
                    "  aud: 'Next-Gen-Scheduling',\n" +
                    "  iat: 1725903517,\n" +
                    "  exp: 1725907117,\n" +
                    "  jti: '0gYs6MY3Ry3Rk1PCXasqoDuv0xEFDsZG',\n" +
                    "  cvs_status_code: '0000',\n" +
                    "  cvs_status_desc: 'Success',\n" +
                    "  cvs_av_original_file_name: 'screenshot',\n" +
                    "  cvs_av_original_file_type: 'jpg',\n" +
                    "  cvs_av_is_file_clean: 'y',\n" +
                    "  cvs_av_file_ref: '1725903517941-screenshot-b9d5afba',\n" +
                    "  cvs_av_file_download_key: '2Yd7bQPSUQgoKZ90StzhGe634IY0ovWX',\n" +
                    "  cvs_av_client_state: 'teststate'\n" +
                    "}";
            String s = encryptWithRSA(payLoad,publicAndPrivateKeys.getPublicKey());
            System.out.println(s);
            String s1 = decryptWithRSA(s, publicAndPrivateKeys.getPrivateKey1());
//            System.out.println(s1);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }







    //code 2

//    public static PrivateKey readPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//
//        String privateKeyPEM = new String(Files.readAllBytes(Paths.get("C:\\Users\\Jerin\\Desktop\\response.txt")));
//
//        if(privateKeyPEM.contains("RSA")){
//
//            privateKeyPEM = privateKeyPEM
//
//                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
//
//                    .replace("-----END RSA PRIVATE KEY-----", "")
//
//                    .replaceAll("\\s+", ""); // Remove all whitespace characters
//
//        }else{
//
//            privateKeyPEM = privateKeyPEM
//
//                    .replace("-----BEGIN PRIVATE KEY-----", "")
//
//                    .replace("-----END PRIVATE KEY-----", "")
//
//                    .replaceAll("\\s+", ""); // Remove all whitespace characters
//
//        }
//
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyPEM));
//
//        return keyFactory.generatePrivate(keySpec);
//
//    }
//
//    public static String decrypt(String encryptedData, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//        cipher.init(Cipher.PRIVATE_KEY, privateKey);
//
//        //byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
//
//        //byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
//
//        System.out.println(encryptedData);
//
//        byte[] decryptedBytes = cipher.doFinal(encryptedData.getBytes(StandardCharsets.UTF_8));
//
//        return new String(decryptedBytes);
//
//    }
//
//    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
//
//        PrivateKey privateKey = readPrivateKey();
//
//        //System.out.println(privateKey);
//
//        String encryptedKey = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.ciTQd381HPWLQ9jIP7SXP_txY9aZbGCv6_rTYTQWs0Y3TH9DHtR3eAJtBQ2OQePIlhRDIkHyren5vxkRVK0GeyEv01S8l58GThOXqrWw6rpRNhmQyHE_BjlA1awDrZX3rn7bkVnJGC_9CEvtM7qofXlbx8OMFoiBKZ41S7kBR92n-97Fp4Q85FfpxCmxqTWDkJtXIAU-tQRvuy3Icwo7WgMeIL6oGydBkP9RLHWl8xA34TlurCQHPCyYhNBDUlkqfE_Ndn9u69FtUMTKrJLSZjzug7JESwKoT_7KmeZHDbcSYQngPiz-FS7GMRlzl4VlFdaNUSuosI7z9uwcnvO_2Q.DVRFftbxPQ-trNfU.PoAB9bEfNJQ2WOuI5_AkQws2BScC2wK5QcCuoLSWLyc2DujknwPUKn_jJU5_Oraa-zy3oPBf9XhxQjVAtX6fcOTGSAzZvgVF_Dz3_0moZVVDDXOqhJN_hOP0G9mkba_nE8dYndGC6FX7cPszqduddQ_tOOyCsiCLYQXTfRV-TnIVSKYiwZ2pi3eKdTg-aL-uQBv19430CzE6H_IPF48knALfrccuKFz1tRSb1tJ5PpUXFQme2172ZMdxcgv5wAenG2oITN9L8b7BHQS_wH_kmcIDYS8hC3NRjFq33YWh4Lr2XD8ck1G4tdDg2c97NOyXmeOi8as-ZmqJt8TC5Q5pNui-2-qyJGFH1l-7Nrzs_wyweS2IZ99ACU2DDSrX9Wt7xn79yOCVDOhInSKLR5apCdace8diPtO4vFC3t88JwZbAjHPCiuLqL1Va70kD-U1Fs9cLDpLf3lKltwYx99tMGi7Lf_VCKxD6rylYcyiuCN-0W3KTqgBTcd48naMRpQ0naWJhaXysOnkOcYQUzzocc_QN4SUb_x25MJ0nBlp9W1abFv1xH-AqzMdQqBqkvvRq2gF0qSqBHIy3iVjRRXPg5m-nd6H7-48wiApzlyyWGUKyO_xcuX8lP_6vbkuMf9f2qZL6xc_fxaavZF9hj0Df2ZQWJq_CGyRmi9lmnmDRZ9XsrI27rJYTQzTwqtkTMi2JyJtHwHDU_78TdnuA9Qqqv1wNQPY2DYnE9v3pCW9J8rfkZa0QuY6H2TpYCUhtt_NBWjiJJN585v90A9YSgHN5h7Nv1dF4CIrLx7rApbTIBSbx3QfTLLpRO03wtddjNRBYOvv_R6peGms2w8lBXl8zpsDMByppMSycu-AhS5AjtGfDr0BwY9bzsOhnwf9NRaWUxm_NpStVGQ.EJ6EnXItl1vhP2iDzt2ZMw";
//
//        System.out.println(decrypt(encryptedKey,privateKey));
//
//    }

}