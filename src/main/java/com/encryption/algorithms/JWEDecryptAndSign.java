package com.encryption.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class JWEDecryptAndSign {

//    public static void decrypt() throws Exception {
//        // Client type
//        String client = "NGS";
//
//        // JWE token
//        String jweToken = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.ciTQd381HPWLQ9jIP7SXP_txY9aZbGCv6_rTYTQWs0Y3TH9DHtR3eAJtBQ2OQePIlhRDIkHyren5vxkRVK0GeyEv01S8l58GThOXqrWw6rpRNhmQyHE_BjlA1awDrZX3rn7bkVnJGC_9CEvtM7qofXlbx8OMFoiBKZ41S7kBR92n-97Fp4Q85FfpxCmxqTWDkJtXIAU-tQRvuy3Icwo7WgMeIL6oGydBkP9RLHWl8xA34TlurCQHPCyYhNBDUlkqfE_Ndn9u69FtUMTKrJLSZjzug7JESwKoT_7KmeZHDbcSYQngPiz-FS7GMRlzl4VlFdaNUSuosI7z9uwcnvO_2Q.DVRFftbxPQ-trNfU.PoAB9bEfNJQ2WOuI5_AkQws2BScC2wK5QcCuoLSWLyc2DujknwPUKn_jJU5_Oraa-zy3oPBf9XhxQjVAtX6fcOTGSAzZvgVF_Dz3_0moZVVDDXOqhJN_hOP0G9mkba_nE8dYndGC6FX7cPszqduddQ_tOOyCsiCLYQXTfRV-TnIVSKYiwZ2pi3eKdTg-aL-uQBv19430CzE6H_IPF48knALfrccuKFz1tRSb1tJ5PpUXFQme2172ZMdxcgv5wAenG2oITN9L8b7BHQS_wH_kmcIDYS8hC3NRjFq33YWh4Lr2XD8ck1G4tdDg2c97NOyXmeOi8as-ZmqJt8TC5Q5pNui-2-qyJGFH1l-7Nrzs_wyweS2IZ99ACU2DDSrX9Wt7xn79yOCVDOhInSKLR5apCdace8diPtO4vFC3t88JwZbAjHPCiuLqL1Va70kD-U1Fs9cLDpLf3lKltwYx99tMGi7Lf_VCKxD6rylYcyiuCN-0W3KTqgBTcd48naMRpQ0naWJhaXysOnkOcYQUzzocc_QN4SUb_x25MJ0nBlp9W1abFv1xH-AqzMdQqBqkvvRq2gF0qSqBHIy3iVjRRXPg5m-nd6H7-48wiApzlyyWGUKyO_xcuX8lP_6vbkuMf9f2qZL6xc_fxaavZF9hj0Df2ZQWJq_CGyRmi9lmnmDRZ9XsrI27rJYTQzTwqtkTMi2JyJtHwHDU_78TdnuA9Qqqv1wNQPY2DYnE9v3pCW9J8rfkZa0QuY6H2TpYCUhtt_NBWjiJJN585v90A9YSgHN5h7Nv1dF4CIrLx7rApbTIBSbx3QfTLLpRO03wtddjNRBYOvv_R6peGms2w8lBXl8zpsDMByppMSycu-AhS5AjtGfDr0BwY9bzsOhnwf9NRaWUxm_NpStVGQ.EJ6EnXItl1vhP2iDzt2ZMw";
//        //String jweToken = "5w1_a33HyHnhxJ1Tn1XCtIkQ3ask2NPxNl9CriPfVnwDeRWaHJNMuBmYyFYyd7CM1XTa3GX_fDRFfW0WWnh_f9v9m2EOtlGPWXIYHI6kkitrQ-pgXnEnFgFVa3jG6I4Rw-X6CWy4QNp-3D6T3AOhW2bFdhJmmHHpbk5q6hzyeh8c8uj0cKhs4wnSk3maxqsYK_AB-GU4fAgMeRcD9nBEAoDw7-pRUn_1dV1o8mQsIZM_r2mCu5SfO-wjl_P4eRCUcV2oYnpejui7Qb997rhKSOyQKsgFrXKnL32Dda6xC7CuQhR-IjDzQt4UQ0nVdEKFMYhXPjx8vWYK-cIi9tzE458-NZ4DPkTRn4_yROFd4Qbqc4b4bRAh1ujppVByPHi-F7JZ09JrraXlQmjpKEQQ2q1bKHXOWjt1qxMjQSrSoxhof8AtHa9JDf8N5O-KZ-hf-1FMNoAc0npiD5j1-FHFOhaS_uN8cO_db-_OaSEKJEzAzJ9XA7POWU1ItFMDoNxs9UadU9wjihnlgXu1iul4JzVOWemomtgrHxcJiNoEHcDiNzKgEfpcKkfhWixW8urPGaQfX5-hpH11COLMgA2K9Ze1OgO8EBgtBvyJDzMCRSUfn901Y_w0mXEjVPxd6GEU_KE8UicHh4Pdy2JbJWaYxbfNzI.IqaUl5_VdZo4zrRI.8SJGGJKrxqb5T_eLLubt_a54yP430axu2HT8fJViQdOjFsqJJcVXaaNj_B22WRLMKlAsj3UOaGDtcYs8VPagtbEBoqmXNSZHUduSMT35TLSMZ0XrwAL62S5mCmLC3qCs39cJ7rhs7TxOiIgJQG6Y3pPZOhX7WwjAyl-3xpVrdXppf4y2KACr2b461jDmxnRM5S6AxGdimbEZz7BZD_EihQKYJI0v06dIuTvS7pMxdCqKTnkps2ruiw9gCX-jfUAbMnIjNhpMfrtW_WcMKlGhGi5Fs9pHiX3S8zQ-jSCRdz1vW_nFTJO7IGOAF6ocb1FNeSQi1bOpVV2ZLsyLb4PQkeEFZUxy4PXAdwpfO2CQw5mzzFt6VvHunTtjV56cTe7Vg3fXLuh3t5q6mn8vWeaFC0pziR-Kj69BbxyUln2-UwkIRx3D_L2zTZI31KKv4XE2m_K3EVaa8Rr2KG8S_6ayr54x1fjpBHG7sqjqjnTuzTkV40_qEYGEBfa1aA3qpQDzVEkNTVeKwXR0UMdXgaS3M3s-3uAMKWFXn0kdVg102L7ibYowT74ZYxQd7KotwaNQDssj9nP2YzBlVB36wmyRg3ST8gUWruBu81lsHb8TJASbA6ttRcJWSbUlJpP-O6YU6iMBv-BB4qkkRNtMCEdNhdkdQyX0TuD2-91dlKUXwUmkarRgaiFdtJACkihOK6AfeNdRtoTBIS9PpWZm5MxBl3MceVMAIwDEmkxxZVIpnrbMoN3Uw4JW7phIUvFmeTL-i7p9g2ig8EMYG5A1U5oV20ILg2w5x5sF-km8OWZtPXU2oeF8BMyyqZPPz8BRJ5ZHuXuNrNEscfcqIaGjrNUBHIOJ6WE0YePK9vdeuB4avo9YHp-yNYoJttUYna8vxg.CSdIoh4wQl0ti8e9dYVP6A";
//        // Path to private key file
//        String clientPrivateKeyPath = "C:\\Users\\Jerin\\Desktop\\response.txt";
//        PrivateKey privateKey = getPrivateKey(clientPrivateKeyPath);
//
//        // Decrypt JWE
//        JsonWebEncryption jwe = new JsonWebEncryption();
//        jwe.setCompactSerialization(jweToken);
//        jwe.setKey(privateKey);
//        String plaintext = jwe.getPlaintextString();
//
//        // Extract JWT from decrypted content
//        String[] parts = plaintext.split("\\.");
//        String base64Payload = parts[1];
//        String decodedPayload = new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8);
//
//        System.out.println("PAYLOAD PLAINTEXT: ");
//        System.out.println(decodedPayload);
//
//        // Create JWT for download
//        Map<String, Object> payloadMap = Map.of(
//                "cvs_av_file_ref", extractFromPayload(decodedPayload, "cvs_av_file_ref"),
//                "x-lob", "security-engineering",
//                "scope", "openid email",
//                "jti", generateJti(),
//                "aud", "CVS-AVScan",
//                "iss", extractFromPayload(decodedPayload, "aud"),
//                "sub", "download_bearer_token"
//        );
//
//        Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey); // Use RSA256 with your private key
//        String jwt = JWT.create()
//                .withPayload(payloadMap)
//                .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1-hour expiration
//                .withHeader(Map.of("alg", "RS256", "typ", "JWT", "kid", getKid(client)))
//                .sign(algorithm);
//
//        System.out.println("BEARER TOKEN FOR DOWNLOAD:");
//        System.out.println(jwt);
//    }
//
//    private static PrivateKey getPrivateKey(String keyFilePath) throws Exception {
//        String key = new String(java.nio.file.Files.readAllBytes(new File(keyFilePath).toPath()));
//        String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
//                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s+", "");
//        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePrivate(keySpec);
//    }
//
//    private static String extractFromPayload(String payload, String key) {
//        // You can use a JSON library like Jackson or org.json to extract key-value pairs
//        return ""; // implement this function
//    }
//
//    private static String generateJti() {
//        return Long.toHexString(Double.doubleToLongBits(Math.random()));
//    }
//
//    private static String getKid(String client) {
//        switch (client) {
//            case "CLAIMS":
//                return "696aeb4a-e264-4028-9881-8c8cba20eb7c";
//            case "ASG":
//                return "vZtyhgxQxErHUsHatSbCVtYYY4Wz7NA3wFr5ocHRnzI";
//            case "DMR":
//                return "6dfe77fb-2117-4266-9aa7-7b6522db85d4";
//            case "VM":
//                return "5v-LDd5_EOPMRgRMe3IeXkOxgUtdH2d5h744sbOpmWQ";
//            case "AQE":
//                return "y4ehf44ljDIrUlFZywhLSwF_Y3BqYp1e-9tvU37Iu0Y";
//            case "NGS":
//                return "YkwvJuq2zBlDaXXcvKRg8hO2vmsCI6ZjQL5I9KoKWng";
//            default:
//                return null;
//        }
//    }
//
//    public static void main(String[] args) throws Exception {
//        decrypt();
//    }



    public static PrivateKey readPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String privateKeyPEM = new String(Files.readAllBytes(Paths.get("C:\\Users\\Jerin\\Desktop\\response.txt")));

        if (privateKeyPEM.contains("RSA")) {
            privateKeyPEM = privateKeyPEM
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s+", ""); // Remove all whitespace characters
        } else {
            privateKeyPEM = privateKeyPEM
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", ""); // Remove all whitespace characters
        }

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static String decryptJWE(String jweString, PrivateKey privateKey) throws JOSEException, ParseException {
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(new RSADecrypter(privateKey));
        return jweObject.getPayload().toString();
    }

    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = readPrivateKey();
        String encryptedToken = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.ciTQd381HPWLQ9jIP7SXP_txY9aZbGCv6_rTYTQWs0Y3TH9DHtR3eAJtBQ2OQePIlhRDIkHyren5vxkRVK0GeyEv01S8l58GThOXqrWw6rpRNhmQyHE_BjlA1awDrZX3rn7bkVnJGC_9CEvtM7qofXlbx8OMFoiBKZ41S7kBR92n-97Fp4Q85FfpxCmxqTWDkJtXIAU-tQRvuy3Icwo7WgMeIL6oGydBkP9RLHWl8xA34TlurCQHPCyYhNBDUlkqfE_Ndn9u69FtUMTKrJLSZjzug7JESwKoT_7KmeZHDbcSYQngPiz-FS7GMRlzl4VlFdaNUSuosI7z9uwcnvO_2Q.DVRFftbxPQ-trNfU.PoAB9bEfNJQ2WOuI5_AkQws2BScC2wK5QcCuoLSWLyc2DujknwPUKn_jJU5_Oraa-zy3oPBf9XhxQjVAtX6fcOTGSAzZvgVF_Dz3_0moZVVDDXOqhJN_hOP0G9mkba_nE8dYndGC6FX7cPszqduddQ_tOOyCsiCLYQXTfRV-TnIVSKYiwZ2pi3eKdTg-aL-uQBv19430CzE6H_IPF48knALfrccuKFz1tRSb1tJ5PpUXFQme2172ZMdxcgv5wAenG2oITN9L8b7BHQS_wH_kmcIDYS8hC3NRjFq33YWh4Lr2XD8ck1G4tdDg2c97NOyXmeOi8as-ZmqJt8TC5Q5pNui-2-qyJGFH1l-7Nrzs_wyweS2IZ99ACU2DDSrX9Wt7xn79yOCVDOhInSKLR5apCdace8diPtO4vFC3t88JwZbAjHPCiuLqL1Va70kD-U1Fs9cLDpLf3lKltwYx99tMGi7Lf_VCKxD6rylYcyiuCN-0W3KTqgBTcd48naMRpQ0naWJhaXysOnkOcYQUzzocc_QN4SUb_x25MJ0nBlp9W1abFv1xH-AqzMdQqBqkvvRq2gF0qSqBHIy3iVjRRXPg5m-nd6H7-48wiApzlyyWGUKyO_xcuX8lP_6vbkuMf9f2qZL6xc_fxaavZF9hj0Df2ZQWJq_CGyRmi9lmnmDRZ9XsrI27rJYTQzTwqtkTMi2JyJtHwHDU_78TdnuA9Qqqv1wNQPY2DYnE9v3pCW9J8rfkZa0QuY6H2TpYCUhtt_NBWjiJJN585v90A9YSgHN5h7Nv1dF4CIrLx7rApbTIBSbx3QfTLLpRO03wtddjNRBYOvv_R6peGms2w8lBXl8zpsDMByppMSycu-AhS5AjtGfDr0BwY9bzsOhnwf9NRaWUxm_NpStVGQ.EJ6EnXItl1vhP2iDzt2ZMw";
        String decryptedPayload = decryptJWE(encryptedToken, privateKey);
        System.out.println("Decrypted Payload: " + decryptedPayload);
    }


}