package tdes;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.swing.JOptionPane;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class TripleDESTest {
    public static void main(String[] args) throws Exception {
        Object[] option = { "Encrypt", "Decrypt" };
        String selectedAction;
        while (true) {
            selectedAction = (String) JOptionPane.showInputDialog(null,
                    "Select:", "3DES Algorithm", JOptionPane.QUESTION_MESSAGE,
                    null, option, option[0]);
            if (selectedAction != null)
                break;
        }
        Security.addProvider(new com.sun.crypto.provider.SunJCE());
        Cipher cipher = Cipher.getInstance("DESEDE/ECB/PKCS5Padding");
        System.out.println(" -- Algorithm --> " + cipher.getAlgorithm());
        Key key;
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream(
                    "3des.key"));
            key = (Key) in.readObject();
            in.close();
        } catch (FileNotFoundException fnfe) {
            KeyGenerator generator = KeyGenerator.getInstance("DESEDE");
            generator.init(new SecureRandom());
            key = generator.generateKey();
            ObjectOutputStream out = new ObjectOutputStream(
                    new FileOutputStream("3des.key"));
            out.writeObject(key);
            out.close();
        }
        if (selectedAction.equals("Encrypt")) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            String text = null;
            while (true) {
                new JOptionPane();
				text = JOptionPane.showInputDialog("TESTING ENCRYPTION:");
                if (text != null)
                    break;
            }
            ;
            cipher.init(Cipher.ENCRYPT_MODE, key);
             
            byte[] stringBytes = text.getBytes("UTF8");
            byte[] raw = cipher.doFinal(stringBytes);
            BASE64Encoder encoder = new BASE64Encoder();
 
            String base64 = encoder.encode(raw);
 
            new JOptionPane();
			JOptionPane.showMessageDialog(null, " Input String: " + text
                    + "\n 3DES [byte]: " + key.getEncoded().length
                    + "\n 3DES [RAW]: " + key.getEncoded()
                    + "\nEncoded Result: " + base64);
            System.out.println("Encryption Result: " + base64);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
 
            String text = null;
            while (true) {
                new JOptionPane();
				text = JOptionPane.showInputDialog("TESTING DECRPTION:");
                if (text != null)
                    break;
            }
            ;
            BASE64Decoder decoder = new BASE64Decoder();
            byte[] raw = decoder.decodeBuffer(text);
            byte[] stringBytes = cipher.doFinal(raw);
 
            String result = new String(stringBytes, "UTF8");
            new JOptionPane();
			JOptionPane.showMessageDialog(null, " Input String: " + text
                    + "\n 3DES [byte]: " + key.getEncoded().length
                    + "\n 3DES [RAW]: " + key.getEncoded() + "\nResult: "
                    + result);
            System.out.println("Decryption Result: " + result);
        }
        System.exit(0);
    }
 
}
