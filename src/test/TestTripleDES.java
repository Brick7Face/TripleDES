package test;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.BeforeClass;
import org.junit.Test;

import tdes.TripleDES; 

public class TestTripleDES {

	//global values for setup
	final static String name = "3des.key";
	static String[] args = {"-g", name};
	static SecretKey key;
	final static File keyFile = new File(name);

	@BeforeClass
	public static void setUp() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		TripleDES.main(args);
		key = TripleDES.readKey(keyFile);
		genKey();
	}

	//setup method to generate key for encryption and ascii modified variants
	public static void genKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		SecretKey thisKey = TripleDES.generateKey();								//generate key to use to encrypt
		TripleDES.writeKey(thisKey, new File("test.key"));							//write key to test.key file
		BufferedReader br = new BufferedReader(new FileReader("test.key"));		
		String line;
		String originalKey = "";
		while ((line = br.readLine()) != null) {									//read in the generated key
			if (line.isEmpty()) {
				break;
			}
			originalKey = originalKey.concat(line);
		}
		br.close();
		
		char[] originalKeyChar = originalKey.toCharArray();							//convert to character array
		originalKeyChar[0]--;														//decrease the first ascii value
		String newKey = new String(originalKeyChar);								//convert back to string
		FileOutputStream out = new FileOutputStream(new File("test1.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[0]++;														//increase first ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("test2.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[originalKeyChar.length - 1]--;								//decrease last ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("test3.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[originalKeyChar.length - 1]++;								//increase last ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("test4.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		//repeat same process for mouse keys
		thisKey = TripleDES.generateKey();											//generate key to use to encrypt
		TripleDES.writeKey(thisKey, new File("mouse.key"));							//write key to test.key file
		br = new BufferedReader(new FileReader("mouse.key"));		
		originalKey = "";
		while ((line = br.readLine()) != null) {									//read in the generated key
			if (line.isEmpty()) {
				break;
			}
			originalKey = originalKey.concat(line);
		}
		br.close();
		
		originalKeyChar = originalKey.toCharArray();								//convert to character array
		originalKeyChar[0]--;														//decrease the first ascii value
		newKey = new String(originalKeyChar);										//convert back to string
		out = new FileOutputStream(new File("mouse1.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[0]++;														//increase first ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("mouse2.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[originalKeyChar.length - 1]--;								//decrease last ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("mouse3.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
		originalKeyChar = originalKey.toCharArray();
		originalKeyChar[originalKeyChar.length - 1]++;								//increase last ascii value
		newKey = new String(originalKeyChar);
		out = new FileOutputStream(new File("mouse4.key"));
		out.write(newKey.getBytes());												//write the key to a new file
		out.close();
		
	}

	/** helper methods **/

	//helper method to set System.in and System.out
	private void setUpFile(String file, String input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		FileOutputStream out = new FileOutputStream(file);
		PrintStream ps = new PrintStream(out);
		System.setOut(ps);
		String inString = input;
		InputStream in = new ByteArrayInputStream(inString.getBytes("UTF-8"));
		System.setIn(in);
	}

	//another helper method to set the file and system.in
	public void setIO() throws IOException {
		File f = new File("test.txt");
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		byte[] raw = new byte[(int)f.length()];
		in.readFully(raw);
		System.setIn(in);
	}

	//helper method - encrypts "test" using test.key for key, writes result to test.txt
	public void hardTestEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
		key = TripleDES.readKey(new File("test.key"));
		setUpFile("test.txt", "test");
		TripleDES.encrypt(key, System.in, System.out);
	}

	//helper method 2 - test encryption of "mouse"
	public void hardTestEncryptTwo() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
		File f = new File("mouse.key");
		key = TripleDES.readKey(f);
		setUpFile("test.txt", "mouse");
		TripleDES.encrypt(key, System.in, System.out);
	}
	
	//helper method to generate a random input string between 2 and 20 characters
	private String genRandString() {
		Random r = new Random();
		int l = r.nextInt(19) + 2;
		byte[] randText = new byte[l];
		new Random().nextBytes(randText);
		return new String(randText, Charset.forName("UTF-8"));
	}

	/** Metamorphic Relation cases **/
	
	/** MR one **/

	//using different key to decrypt cipher should NOT equal "test"
	@Test
	public void testMROneOne() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncrypt();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.generateKey(), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("test"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with front ASCII value decreased by 1, should not be same
	@Test
	public void testMROneTwo() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncrypt();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("test1.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("test"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with front ASCII value increased by 1, should not be same
	@Test
	public void testMROneThree() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncrypt();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("test2.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("test"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with back ASCII value decreased by 1, should not be same
	@Test
	public void testMROneFour() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncrypt();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("test3.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("test"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with back ASCII value increased by 1, should not be same
	@Test
	public void testMROneFive() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncrypt();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("test4.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("test"));		//if failed, mutant killed
		br.close();
	}

	//test a different key for the mouse cipher, should not be same
	@Test
	public void testMROneSix() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncryptTwo();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.generateKey(), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("mouse"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with first ASCII value decreased by 1, should not be same
	@Test
	public void testMROneSeven() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncryptTwo();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("mouse1.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("mouse"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with first ASCII value increased by 1, should not be same
	@Test
	public void testMROneEight() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncryptTwo();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("mouse2.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("mouse"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with last ASCII value decreased by 1, should not be same
	@Test
	public void testMROneNine() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncryptTwo();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("mouse3.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("mouse"));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with last ASCII value increased by 1, should not be same
	@Test
	public void testMROneTen() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//set up initial input in test.txt
		hardTestEncryptTwo();

		//set System.in to the cipher
		setIO();

		//test a new key decryption
		TripleDES.decrypt(TripleDES.readKey(new File("mouse4.key")), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String s = br.readLine();
		assertTrue(!s.equals("mouse"));		//if failed, mutant killed
		br.close();
	}

	/** MR Two **/
	
	//encrypt "tdst" and make sure first and last characters of cipher are different (fully compared later)
	@Test
	public void testMRTwoOne() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//initial input in test.txt
		hardTestEncrypt();

		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String testCipher = br.readLine();
		br.close();

		//test that encrypting a similar word to "test" doesn't have a similar cipher as "test" - compare first and last chars because
		//they are the same letters for "test"
		setUpFile("test.txt", "tdst");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		char[] tcArr = testCipher.toCharArray();
		char[] cArr = cipher.toCharArray();
		assertTrue((tcArr[0] != cArr[0]) && (tcArr[tcArr.length - 1] != cArr[cArr.length - 1]));
		br.close();
	}

	//similar to the first test, encrypt "tesu" and test
	@Test
	public void testMRTwoTwo() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();	

		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String testCipher = br.readLine();
		br.close();

		//similar test, but test if different position in "test" was altered
		setUpFile("test.txt", "tesu");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		char[] tcArr = testCipher.toCharArray();
		char[] cArr = cipher.toCharArray();
		assertTrue((tcArr[0] != cArr[0]) && (tcArr[tcArr.length - 2] != cArr[cArr.length - 2]));
		br.close();
	}

	//using similar cipher should not decrypt to string similar to test
	@Test
	public void testMRTwoThree() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		String testPlaintext = "test";
		char[] c = cipher.toCharArray();
		c[0]--;
		String newCipher = new String(c);

		//same idea as first test but using cipher instead of plaintext
		setUpFile("test.txt", newCipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		char[] pArr = plaintext.toCharArray();
		char[] tpArr = testPlaintext.toCharArray();
		assertTrue((tpArr[0] != pArr[0]) && (tpArr[tpArr.length - 1] != pArr[pArr.length - 1]));
		br.close();
	}

	//similar to last test, using cipher "V¢o˜å•¾×"
	@Test
	public void testMRTwoFour() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		String testPlaintext = "test";
		char[] c = cipher.toCharArray();
		c[c.length - 1]--;
		String newCipher = new String(c);

		//same as before but with a different cipher
		setUpFile("test.txt", newCipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		char[] pArr = plaintext.toCharArray();
		char[] tpArr = testPlaintext.toCharArray();
		assertTrue((tpArr[0] != pArr[0]) && (tpArr[tpArr.length - 1] != pArr[pArr.length - 1]));
		br.close();
	}

	//encrypt random string, get cipher, change cipher by 1 character, decrypt, compare string original, should not be equal
	@Test
	public void testMRTwoFive() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//generate random string, encrypt, change cipher, decrypt, not equal to original
		String plaintext = genRandString();
		setUpFile("test.txt", plaintext);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		char[] c = cipher.toCharArray();
		int pos = new Random().nextInt((c.length - 1));
		int ascii = (int) c[pos];
		c[pos] = (char) ascii++;
		cipher = new String(c);
		setUpFile("test.txt", cipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.decrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newPlaintext = br.readLine();
		assertTrue(newPlaintext != plaintext);
		br.close();
	}

	//similar to the first test but using a similarity counter
	@Test
	public void testMRTwoSix() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		//initial input in test.txt
		hardTestEncrypt();

		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String testCipher = br.readLine();
		br.close();

		//test that encrypting a similar word to "test" doesn't have a similar cipher as "test" using similarity counter
		setUpFile("test.txt", "tdst");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		char[] tcArr = testCipher.toCharArray();
		char[] cArr = cipher.toCharArray();
		int simCount = 0;								//counter for same letters
		if (tcArr.length == cArr.length) {				//if lengths are not equal, then words aren't same; if they are, check letters
			for (int i = 0; i < tcArr.length; i++) {		//count similar letters
				if (tcArr[i] == cArr[i]) {
					simCount++;
				}
			}
		}
		assertTrue(simCount < (cArr.length / 2 + 1)); 	//if the similarity counter is greater than half the length of the original plus one, too similar
		br.close();
	}

	//similar to the first test, encrypt "tesu" and test using similarity counter
	@Test
	public void testMRTwoSeven() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();	

		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String testCipher = br.readLine();
		br.close();

		//similar test, but test if different position in "test" was altered
		setUpFile("test.txt", "tesu");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		char[] tcArr = testCipher.toCharArray();
		char[] cArr = cipher.toCharArray();
		int simCount = 0;								//counter for same letters
		if (tcArr.length == cArr.length) {				//if lengths are not equal, then words aren't same; if they are, check letters
			for (int i = 0; i < tcArr.length; i++) {		//count similar letters
				if (tcArr[i] == cArr[i]) {
					simCount++;
				}
			}
		}
		assertTrue(simCount < (cArr.length / 2 + 1)); 	//if the similarity counter is greater than half the length of the original plus one, too similar
		br.close();
	}

	//using similar cipher should not decrypt to string with similar to test using similarity counter
	@Test
	public void testMRTwoEight() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		String testPlaintext = "test";
		char[] c = cipher.toCharArray();
		c[0]--;
		String newCipher = new String(c);

		//same idea as first test but using cipher instead of plaintext
		setUpFile("test.txt", newCipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		char[] pArr = plaintext.toCharArray();
		char[] tpArr = testPlaintext.toCharArray();
		int simCount = 0;								//counter for same letters
		if (tpArr.length == pArr.length) {				//if lengths are not equal, then words aren't same; if they are, check letters
			for (int i = 0; i < tpArr.length; i++) {		//count similar letters
				if (tpArr[i] == pArr[i]) {
					simCount++;
				}
			}
		}
		assertTrue(simCount < (pArr.length / 2 + 1)); 	//if the similarity counter is greater than half the length of the original plus one, too similar
		br.close();
	}

	//similar to last test, using similar cipher and using similarity counter
	@Test
	public void testMRTwoNine() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		String testPlaintext = "test";
		char[] c = cipher.toCharArray();
		c[c.length - 1]--;
		String newCipher = new String(c);

		//same as before but with a different cipher
		setUpFile("test.txt", newCipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		char[] pArr = plaintext.toCharArray();
		char[] tpArr = testPlaintext.toCharArray();
		int simCount = 0;								//counter for same letters
		if (tpArr.length == pArr.length) {				//if lengths are not equal, then words aren't same; if they are, check letters
			for (int i = 0; i < tpArr.length; i++) {		//count similar letters
				if (tpArr[i] == pArr[i]) {
					simCount++;
				}
			}
		}
		assertTrue(simCount < (pArr.length / 2 + 1)); 	//if the similarity counter is greater than half the length of the original plus one, too similar
		br.close();
	}

	//randomly generate cipher, get decryption, change cipher by 1 character, decrypt, compare both decryptions
	@Test
	public void testMRTwoTen() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		//generate random cipher, decrypt, change cipher, decrypt, not equal to original
		String cipher = genRandString();
		setUpFile("test.txt", cipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.decrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		br.close();

		char[] c = cipher.toCharArray();
		int pos = new Random().nextInt((c.length - 1));
		int ascii = (int) c[pos];
		c[pos] = (char) ascii++;
		cipher = new String(c);
		setUpFile("test.txt", cipher);
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.decrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newPlaintext = br.readLine();
		assertTrue(newPlaintext.equals(plaintext));
		br.close();
	}

	/** MR Three **/
	
	//Generating new key and encrypting "test" should not result in same cipher when using the first key
	@Test
	public void testMRThreeOne() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "test");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.generateKey(), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with front ASCII value decreased by 1, should not be same
	@Test
	public void testMRThreeTwo() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "test");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("test1.key")), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with front ASCII value increased by 1, should not be same
	@Test
	public void testMRThreeThree() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		//generate correct cipher, read it in
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		
		/* OLD STUFF
		//experimental
		File f = new File("test.txt");
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		byte[] rawCipher = new byte[(int)f.length()];
		in.readFully(rawCipher);
		in.close();
		System.out.flush();
		System.in.reset();
		*/
		
		
		//set System.in to "test" and System.out to the file test.txt (deletes previous file contents)
		setUpFile("test.txt", "test");

		//test a new key encryption
		SecretKey key2 = TripleDES.readKey(new File("test2.key"));
		TripleDES.encrypt(key2, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		
		
		/* OLD STUFF
		//experimental
		in = new DataInputStream(new FileInputStream(f));
		byte[] newRawCipher = new byte[(int)f.length()];
		in.readFully(newRawCipher);
		in.close();
		int simCount = 0;
		int simCount2 = 0;
		for (int i = 0; i < rawCipher.length; i++) {		//count number of same bytes
			if (rawCipher[i] == newRawCipher[i]) {
				simCount++;
			}
			if ((int)rawCipher[i] == (int)newRawCipher[i]) {	//count number of same ascii values
				simCount2++;
			}
		}
		//assertTrue(key != key2);	//passes - keys are not equal (can be verified by looking at test.key and test2.key too)
		//assertTrue(simCount < (rawCipher.length / 2));	//assess whether bytes are different - fails (though keys are different)
		//assertTrue(simCount2 < (rawCipher.length / 2));	//same as bytes, but with ascii values; fails
		*/
		
		
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with back ASCII value decreased by 1, should not be same
	@Test
	public void testMRThreeFour() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncrypt();
		
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "test");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("test1.key")), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//test a key similar to the real key with back ASCII value increased by 1, should not be same
	@Test
	public void testMRThreeFive() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		//encrypt "test" using test.key, write resulting cipher to file
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "test");		//reset file, in and out

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("test4.key")), System.in, System.out);		//encrypt "test" using similar but different key, write result to file
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//should be different, since key was different
		br.close();
	}

	//generate and encrypt random string, use different key to decrypt, and make sure they are not equal
	@Test
	public void testMRThreeSix() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		//generate and encrypt random string
		key = TripleDES.generateKey();
		String plaintext = genRandString();
		setUpFile("test.txt", plaintext);
		TripleDES.encrypt(key, System.in, System.out);

		//make sure decrypting with different key is not the same
		TripleDES.decrypt(TripleDES.generateKey(), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String newPlaintext = br.readLine();
		assertTrue(!plaintext.equals(newPlaintext));		//if failed, mutant killed
		br.close();
	}

	//generate and decrypt random string, use different key to encrypt, and make sure they are not equal
	@Test
	public void testMRThreeSeven() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		//generate and decrypt random string
		key = TripleDES.generateKey();
		String cipher = genRandString();
		setUpFile("test.txt", cipher);
		TripleDES.decrypt(key, System.in, System.out);

		//make sure encrypting with different key is not the same
		TripleDES.encrypt(TripleDES.generateKey(), System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//repeat one with "mouse" for plaintext
	@Test
	public void testMRThreeEight() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncryptTwo();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "mouse");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.generateKey(), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//repeat two with "mouse" for plaintext
	@Test
	public void testMRThreeNine() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncryptTwo();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "mouse");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("mouse1.key")), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//repeat three with "mouse" for plaintext
	@Test
	public void testMRThreeTen() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncryptTwo();
		
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		System.out.flush();					//clear output in case anything left over
		
		setUpFile("test.txt", "mouse");		//setup new file for new cipher

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("mouse2.key")), System.in, System.out);		//encrypt with a slightly different key
		BufferedReader b = new BufferedReader(new FileReader("test.txt"));
		String newCipher = b.readLine();
		assertTrue(!cipher.equals(newCipher));		//somehow still equal though key is slightly different
		b.close();
	}

	//repeat 4 with mouse
	@Test
	public void testMRThreeEleven() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "mouse");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("mouse3.key")), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

	//repeat 5 with mouse
	@Test
	public void testMRThreeTwelve() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException {
		hardTestEncrypt();
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();		//the original cipher
		br.close();
		setUpFile("test.txt", "mouse");

		//test a new key encryption
		TripleDES.encrypt(TripleDES.readKey(new File("mouse4.key")), System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String newCipher = br.readLine();
		assertTrue(!cipher.equals(newCipher));		//if failed, mutant killed
		br.close();
	}

}
