import org.apache.poi.hwpf.HWPFDocument;
import org.apache.poi.hwpf.extractor.WordExtractor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

public class Hybrid {

    public static void main(String[] args) throws Exception {
        AES_GCM aes = new AES_GCM();
        RSA rsa = new RSA();
        SHA_256 sha = new SHA_256();
        byte[] content;
        System.out.print("Menu :\n1. Encrypt File\n2. Decrypt File\nChoose(1/2):");
        Scanner sc = new Scanner(System.in);
        int ch = sc.nextInt();
        switch (ch) {
            case 1:
                System.out.println("Select File Type:\n1.Text/t(.txt)\n 2.Document/t(.doc/.docx/.pdf)\n3.Image/t(.jpg/.jpeg/.png)");
                int ch1 = sc.nextInt();
                System.out.println("Provide the File Path: ");
                String filepath = sc.nextLine();
                switch (ch1) {
                    case 1:
                        String str = textfile(filepath);
                        content = str.getBytes();
                        break;
                    case 2:
                        str = Arrays.toString(docfile(filepath));
                        str = str.substring(1, str.length()-1);
                        content = str.getBytes();
                        break;
                    case 3:
                        content = imgfile(filepath);
                        break;
                    default:
                        throw new IllegalStateException("Unexpected value: " + ch1);
                }

                byte[] cipherText = AES_GCM.encrypt(content, AES_GCM.AESKey(), AES_GCM.IV);
                byte[] keyarr = AES_GCM.AESKey().getEncoded();
                String AESKeyStr = Base64.getEncoder().encodeToString(keyarr);
                String contentencrypt = Base64.getEncoder().encodeToString(cipherText);
                Map<String, Object> keys = RSA.getRSAKeys();
                PublicKey publicKey1 = (PublicKey) keys.get("recieverpublic");
                PublicKey publicKey2 = (PublicKey) keys.get("senderpublic");
                String keyencrypt = RSA.encrypt(AESKeyStr, publicKey1);
                System.out.println("File Encrypted Successfully");
                String sign = SHA_256.toHexString(SHA_256.getSHA(keyencrypt));
                System.out.println("Signature Generated Successfully");
                BufferedWriter writer = new BufferedWriter(new FileWriter("EncyrptedOutput.txt"));
                writer.write(publicKey2 + " @@ " + Arrays.toString(AES_GCM.IV) + " @@ " + contentencrypt + " @@ " + keyencrypt + " @@$$ " + sign);
                break;
            case 2 :
                System.out.println("Provide the Filepath :");
                filepath = sc.nextLine();
                String str = textfile(filepath);
                String[] strarr = str.split(" @@ ");
                String strcache = strarr[0];
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(strcache));
                PublicKey senderpublic = (PublicKey) kf.generatePublic(keySpecX509);
                strcache = strarr[1];
                byte[] IVDecrypt = strcache.getBytes();
                strcache = strarr[2];
                byte[] contentcache = strcache.getBytes();
                strcache = strarr[3];
                byte[] decodedKey = Base64.getDecoder().decode(strcache);
                SecretKey rcvkey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
                String contentdecrypt = aes.decrypt(contentcache, rcvkey, IVDecrypt);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + ch);
        }
    }

    public static String textfile(String filepath) {
        Path path = Paths.get(filepath);
        StringBuilder content = null;
        try(BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)){


            String currentLine;
            while((currentLine = reader.readLine()) != null){//while there is content on the current line
                assert false;
                content.append(currentLine);
            }
        }catch(IOException ex){
            ex.printStackTrace(); //handle an exception here
        }
        assert false;
        return content.toString();
    }
    public static String[] docfile(String filepath) throws IOException {
            File file;
        file = new File(filepath);
                FileInputStream fis = new FileInputStream(file.getAbsolutePath());
                HWPFDocument document = new HWPFDocument(fis);
                WordExtractor extractor = new WordExtractor(document);

        return extractor.getParagraphText();
        }

    public static byte[] imgfile(String filepath) throws Exception{
        BufferedImage bImage = ImageIO.read(new File(filepath));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(bImage, "jpg", bos );
        return bos.toByteArray();
    }
}

