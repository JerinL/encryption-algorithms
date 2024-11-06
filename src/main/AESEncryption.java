import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncryption {
	
	private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 12 bytes for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
    private static final String BASE64_SECRET_KEY = "ZX3rCXiNAUWfjzcYoB2Ibw==";
    
    private static SecretKeySpec getSecretKey() {
    	
        //byte[] decodedKey = Base64.getDecoder().decode(BASE64_SECRET_KEY);
        byte[] decodedKey = Base64.getDecoder().decode(BASE64_SECRET_KEY);
        System.out.println("Decoded key length: " + decodedKey.length + " bytes");
        return new SecretKeySpec(decodedKey, "AES");
    }

    
    public static String encrypt(String plainText) throws Exception {
        SecretKey key = getSecretKey();
        
        // Generate a random IV for each encryption
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] encryptedText = cipher.doFinal(plainText.getBytes());
        
        // Concatenate IV and encrypted text for storage/transmission
        byte[] ivAndCipherText = new byte[GCM_IV_LENGTH + encryptedText.length];
        System.arraycopy(iv, 0, ivAndCipherText, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedText, 0, ivAndCipherText, GCM_IV_LENGTH, encryptedText.length);

        // Return Base64 encoded IV and ciphertext
        return Base64.getEncoder().encodeToString(ivAndCipherText);
    }
    
    
    
    public static String decrypt(String encryptedText) throws Exception {
        SecretKey key = getSecretKey();
        
        // Decode Base64 to get IV and ciphertext
        byte[] ivAndCipherText = Base64.getDecoder().decode(encryptedText);
        
        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] cipherText = new byte[ivAndCipherText.length - GCM_IV_LENGTH];
        System.arraycopy(ivAndCipherText, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(ivAndCipherText, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        byte[] decryptedText = cipher.doFinal(cipherText);
        return new String(decryptedText);
    }

   private static final int AES_KEY_SIZE = 128;
      
    private static SecretKeySpec getSecretKey() {
        byte[] decodedKey = Base64.getDecoder().decode(BASE64_SECRET_KEY);
        return new SecretKeySpec(decodedKey, "AES");
    }
    
    public static void main(String[] args) {
        try {
            String originalText = "E:\\pms_issue_attachment\\PMS-jerin-Backup.sql";
            System.out.println("Original Text: " + originalText);

            // Encrypt the text
            String encryptedText = encrypt(originalText);
            System.out.println("Encrypted Text: " + encryptedText);

            // Decrypt the text
            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

  //generate Secret key code 
  
    // private static final int AES_KEY_SIZE = 128;
    
    // private static final String BASE64_SECRET_KEY = "C6OGf+b/NlVMg8gGvc/jtFEo4csk6EsWEipPD7S5rMg=";
    
    
    // private static SecretKeySpec getSecretKey() {
    //     byte[] decodedKey = Base64.getDecoder().decode(BASE64_SECRET_KEY);
    //     return new SecretKeySpec(decodedKey, "AES");
    // }
    
    // public static void main(String[] args) throws Exception {
    //     // Generate AES Key
    //     KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    //     keyGen.init(AES_KEY_SIZE);
    //     SecretKey secretKey = keyGen.generateKey();

    //     // Encode the key in Base64
    //     String base64EncodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
    //     System.out.println("Base64 Encoded AES Key: " + base64EncodedKey);
    // }




// AES Encription ECB mode

    //   private static final String ALGORITHM = "AES";
    // private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // public static String encrypt(String plainText, String key) throws Exception {
    //     Key secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    //     Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    //     cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    //     byte[] byteData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
    //     String base64EncryptedData = Base64.getEncoder().encodeToString(byteData);
    //     return base64EncryptedData;
    // }

    // public static String decrypt(String  encryptedData, String key) throws Exception {
    //     Key secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    //     Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    //     cipher.init(Cipher.DECRYPT_MODE, secretKey);

    //     byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
    //     return new String(decryptedBytes, StandardCharsets.UTF_8);
    // }
    
    // public static void main(String[] args) {
    // 	String plaintext = "E:\\pms_issue_attachment\\PMS-Data-Backup.sql";
    // 	String key = "1234567890123456";

    // 	try {
    // 	    String encryptedData = encrypt(plaintext, key);
    // 	    System.out.println("Encrypted bytes: " + encryptedData);

    // 	    String decryptedText = decrypt(encryptedData, key);
    // 	    System.out.println("Decrypted text: " + decryptedText);
    // 	} catch (Exception e) {
    // 	    e.printStackTrace();
    // 	}
    // }

}
