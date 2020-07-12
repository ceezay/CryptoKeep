import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

// Java 8 example for RSA encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSA {

    // Get RSA keys. Uses key size of 2048.
    static Map<String,Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();
        KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey2 = keyPair1.getPrivate();
        PublicKey publicKey2 = keyPair1.getPublic();
        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("recieverprivate", privateKey1);
        keys.put("recieverpublic", publicKey1);
        keys.put("senderprivate", privateKey2);
        keys.put("senderpublic", publicKey2);

        return keys;
    }

    // Decrypt using RSA public key
    private static String decrypt(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    // Encrypt using RSA public key
    static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

}