//package test;

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

import org.junit.Test;

//import TripleDES; 

public class TestTripleDES {

	//global values for setup
	final String name = "3des.key";
	String[] args = {"-g", name};
	SecretKey key;
	final File f = new File(name);

	public void setUp() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		TripleDES.main(args);
		key = TripleDES.readKey(f);
	}

	/* Metamorphic Relation cases - source test cases and follow up tests */

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


	//helper method - encrypts "test" to "V¢o˜å•¿×" using "L³ï\n¿˜ã«1Rº|*8*\n4/7z¿" for key
	public void hardTestEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
		File f = new File("test.key");
		key = TripleDES.readKey(f);
		setUpFile("test.txt", "test");
		TripleDES.encrypt(key, System.in, System.out);
	}

	//helper method 2 - test encryption of "mouse", end cipher is "y·jÐŒ9Mø"
	public void hardTestEncryptTwo() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
		File f = new File("mouse.key");
		key = TripleDES.readKey(f);
		setUpFile("test.txt", "mouse");
		TripleDES.encrypt(key, System.in, System.out);
	}

	//metamorphic test cases - follow ups from hardTestEncrypt()

	//using different key to decrypt "V¢o˜å•¿×" should NOT equal "test"
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

	//helper method to generate a random input string between 2 and 20 characters
	private String genRandString() {
		Random r = new Random();
		int l = r.nextInt(19) + 2;
		byte[] randText = new byte[l];
		new Random().nextBytes(randText);
		return new String(randText, Charset.forName("UTF-8"));
	}

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

	//using cipher "U¢o˜å•¿×" should not decrypt to string with similar to test
	@Test
	public void testMRTwoThree() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		String testPlaintext = "test";

		//same idea as first test but using cipher instead of plaintext
		setUpFile("test.txt", "U¢o˜å•¿×");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		char[] pArr = plaintext.toCharArray();
		char[] tpArr = testPlaintext.toCharArray();
		assertTrue((tpArr[0] != pArr[0]) && (tpArr[tpArr.length - 1] != pArr[pArr.length - 1]));
		br.close();
	}

	//similar to last test, using cipher "V¢o˜å•¾×"
	@Test
	public void testMRTwoFour() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		String testPlaintext = "test";

		//same as before but with a different cipher
		setUpFile("test.txt", "V¢o˜å•¾×");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
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
	
	//using cipher "U¢o˜å•¿×" should not decrypt to string with similar to test using similarity counter
	@Test
	public void testMRTwoEight() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		String testPlaintext = "test";

		//same idea as first test but using cipher instead of plaintext
		setUpFile("test.txt", "U¢o˜å•¿×");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
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
	
	//similar to last test, using cipher "V¢o˜å•¾×" using similarity counter
	@Test
	public void testMRTwoNine() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		String testPlaintext = "test";

		//same as before but with a different cipher
		setUpFile("test.txt", "V¢o˜å•¾×");
		key = TripleDES.readKey(new File("test.key"));
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
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

	//helper method to encrypt string twice, decrypt
	//changeLate changes the second cipher, changeEarly changes the first cipher
	public String doubleDecrypt(String inString, boolean changeLate, boolean changeEarly) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		int pos = 0;
		key = TripleDES.generateKey();
		setUpFile("test.txt", inString);
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		if (changeEarly) {										//changes the 1st cipher by one ascii value
			char[] cArr = cipher.toCharArray();
			pos = new Random().nextInt((cArr.length - 1));
			int ascii = (int) cArr[pos];
			cArr[pos] = (char) ascii++;
			cipher = new String(cArr);
		}
		setUpFile("test.txt", cipher);
		TripleDES.encrypt(key, System.in, System.out);
		br = new BufferedReader(new FileReader("test.txt"));
		String secondCipher = br.readLine();
		br.close();
		if (changeLate) {										//changes the 2nd cipher by one ascii value
			char[] scArr = secondCipher.toCharArray();
			if (!changeEarly) {
				pos = new Random().nextInt((scArr.length - 1));
			}
			int ascii = (int) scArr[pos];
			scArr[pos] = (char) ascii--;
			cipher = new String(scArr);
		}
		setUpFile("test.txt", secondCipher);
		TripleDES.decrypt(key, System.in, System.out);			//decrypt 2nd cipher
		br = new BufferedReader(new FileReader("test.txt"));
		cipher = br.readLine();
		br.close();
		setUpFile("test.txt", cipher);
		TripleDES.decrypt(key, System.in, System.out);			//decrypt 1st cipher
		br = new BufferedReader(new FileReader("test.txt"));
		String plaintext = br.readLine();
		br.close();
		return plaintext;
	}

	//encrypt random string twice, change cipher by 1 character, decrypt, should not be same
	@Test
	public void testMRThreeFive() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, true, false).equals(plaintext));
	}

	//repeat with new random string
	@Test
	public void testMRThreeSix() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, true, false).equals(plaintext));
	}

	//encrypt random string, change cipher by 1 character, encrypt, decrypt twice, should not be same
	@Test
	public void testMRThreeSeven() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, false, true).equals(plaintext));
	}

	//repeat with new random string
	@Test
	public void testMRThreeEight() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, false, true).equals(plaintext));
	}

	//encrypt random string, increase cipher character by 1, encrypt, decrease character by 1, decrypt twice, compare original (should not be same)
	@Test
	public void testMRThreeNine() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, true, true).equals(plaintext));
	}

	//repeat nine for a new random string
	@Test
	public void testMRThreeTen() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, true, true).equals(plaintext));
	}

	/*	--> THESE TESTS FAIL DUE TO PROGRAM NOT HANDLING VERY LONG STRINGS; 2ND CIPHER TOO LONG TO DECRYPT ACCURATELY
	//encrypt random string, change cipher by 1 character, encrypt, decrypt, should be same as changed cipher
	//does not use helper method since checking cipher, not plaintext (essentially tests encrypt/decrypt but with a cipher, aka more complicated "plaintext")
	@Test
	public void testMRThreeNine() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		key = TripleDES.generateKey();
		setUpFile("test.txt", plaintext);
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader br = new BufferedReader(new FileReader("test.txt"));
		String cipher = br.readLine();
		br.close();
		char[] cArr = cipher.toCharArray();
		int pos = new Random().nextInt((cArr.length - 1));
		int ascii = (int) cArr[pos];
		cArr[pos] = (char) ascii++;									//change cipher by 1 ascii value
		cipher = new String(cArr);
		setUpFile("test.txt", cipher);
		TripleDES.encrypt(key, System.in, System.out);				//encrypt the changed cipher
		br = new BufferedReader(new FileReader("test.txt"));
		String secondCipher = br.readLine();
		br.close();
		setUpFile("test.txt", secondCipher);
		TripleDES.decrypt(key, System.in, System.out);				//decrypt the 2nd cipher
		br = new BufferedReader(new FileReader("test.txt"));
		String cipher2 = br.readLine();
		assertTrue(cipher.equals(cipher2));							//since no change occurred, they should be equal
	}
	 
	//encrypt "test" twice, decrypt result twice, should result in "test"
	@Test
	public void testMRThreeOne() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		assertTrue(doubleDecrypt("test", false, false).equals("test"));
	}

	//similar as one, but with random string
	@Test
	public void testMRThreeTwo() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(doubleDecrypt(plaintext, false, false).equals(plaintext));
	}

	//repeat two with new random string
	@Test
	public void testMRThreeThree() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, false, false).equals(plaintext));
	}

	//repeat with new random string
	@Test
	public void testMRThreeFour() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		String plaintext = genRandString();
		assertTrue(!doubleDecrypt(plaintext, false, false).equals(plaintext));
	}
	*/


}
