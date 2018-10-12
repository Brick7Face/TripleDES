package tdes;

/**
 *
 * @author asn
 */
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Matthew H. Wagner
 * @customized Aditya Satrio N. (:D hehe)
 */
public class TripleDesBouncyCastle {

    private static String TRIPLE_DES_TRANSFORMATION = "DESede/ECB/PKCS7Padding";
    private static String ALGORITHM = "DESede";
    private static String BOUNCY_CASTLE_PROVIDER = "BC";
    private static final String UNICODE_FORMAT = "UTF8";
    public static final String PASSWORD_HASH_ALGORITHM = "SHA";

    /* To do : initialize bouncy castle provide
     * 
     */
    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /*
     * To do : encrypt plaintext using 3Des algorithm 
     */
    private static byte[] encode(byte[] input, String key) throws IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        init();
        Cipher encrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        //hash key to sha, and init encrypter  
        encrypter.init(Cipher.ENCRYPT_MODE, buildKey(key.toCharArray()));
        //encrypt 
        return encrypter.doFinal(input);
    }

    /*
     * To do : decrypt plaintext using 3Des algorithm 
     */
    private static byte[] decode(byte[] input, String key) throws IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        init();
        Cipher decrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        //hash key to sha, and init decrypter 
        decrypter.init(Cipher.DECRYPT_MODE, buildKey(key.toCharArray()));
        //decrypt
        return decrypter.doFinal(input);
    }

    /*
     *to do : string to byte , UTF-8 format
     */
    private static byte[] getByte(String string) throws UnsupportedEncodingException {
        return string.getBytes(UNICODE_FORMAT);
    }

    /*
     * to do : byte to String
     */
    private static String getString(byte[] byteText) {
        return new String(byteText);
    }

    /*
     * generate has key using SHA
     */
    private static Key buildKey(char[] password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        init();
        MessageDigest digester = MessageDigest.getInstance(PASSWORD_HASH_ALGORITHM);
        digester.update(String.valueOf(password).getBytes(UNICODE_FORMAT));
        byte[] key = digester.digest();

        //3des key using 24 byte, convert to 24 byte  
        byte[] keyDes = Arrays.copyOf(key, 24);
        SecretKeySpec spec = new SecretKeySpec(keyDes, ALGORITHM);
        return spec;
    }

    /*
     * encrypt using 3 des
     */
    public static String encrypt(String plainText, String key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        byte[] encryptedByte = TripleDesBouncyCastle.encode(getByte(plainText), key);
        return Hex.encodeHexString(encryptedByte);
    }

    /*
     * decrypt using 3 des
     */
    public static String decrypt(String cipherText, String key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, DecoderException {
        byte[] decryptedByte = TripleDesBouncyCastle.decode(Hex.decodeHex(cipherText.toCharArray()), key);
        return getString(decryptedByte);
    }

    /*
     * generate has key using SHA
     */
    public String generateSHA(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        init();
        MessageDigest digester = MessageDigest.getInstance(PASSWORD_HASH_ALGORITHM);
        digester.update(String.valueOf(password.toCharArray()).getBytes(UNICODE_FORMAT));
        byte[] key = digester.digest();
        return Hex.encodeHexString(key);
    }
}