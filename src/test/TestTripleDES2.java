package test;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.Test;

import tdes.TripleDES;

public class TestTripleDES2 {
	
	//global values for setup
		final String name = "3des.key";
		String[] args = {"-g", name};
		SecretKey key;
		final File f = new File(name);
		
		@Test
		public void setUp() {
			TripleDES.main(args);
			try {
				key = TripleDES.readKey(f);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		
	/* Dummy test cases */
	/******************************************************************************/
	
	//tests if key generates w/DESede algorithm in raw format, and generates a new key from setup
	@Test
	public void testGenerateKey() throws InvalidKeyException, InvalidKeySpecException, IOException {
		try {
			assert(TripleDES.generateKey() != null);
			SecretKey key1 = TripleDES.readKey(f);
			assert(key1 != key);
			assert(TripleDES.generateKey().getAlgorithm().equals("DESede"));
			assert(TripleDES.generateKey().getFormat().equals("RAW"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	
	//tests to make sure correct conditional statements are executed given the various cli args
	@Test
	public void testArgsConditions() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		key = TripleDES.readKey(f);
		args[0] = "-g"; 
		TripleDES.main(args);
		SecretKey key1 = TripleDES.readKey(f);
		assert(key1 != key);
		
		TripleDES.generateKey();
		args[0] = "-e";
		FileOutputStream out = new FileOutputStream("test.txt");
		PrintStream ps = new PrintStream(out);
		System.setOut(ps);
		String inString = "test";
		InputStream in = new ByteArrayInputStream(inString.getBytes());
		System.setIn(in);
		BufferedReader r = new BufferedReader(new FileReader("test.txt"));
		TripleDES.main(args);
		String line = r.readLine();
		assert(line != null);
		
		TripleDES.generateKey();
		args[0] = "-d";
		BufferedReader r2 = new BufferedReader(new FileReader("test.txt"));
		TripleDES.main(args);
		String line2 = r2.readLine();
		assert(line2 != null);
		
		r.close();
		r2.close();
	}
	
	//helper method
	private void setUpFile(String file, String input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		FileOutputStream out = new FileOutputStream(file);
		PrintStream ps = new PrintStream(out);
		System.setOut(ps);
		String inString = input;
		InputStream in = new ByteArrayInputStream(inString.getBytes());
		System.setIn(in);
	}
	
	//test to make sure encrypt does so consistently when using the same key
	@Test
	public void testEncrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		key = TripleDES.generateKey();
		setUpFile("test.txt", "test");
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader reader1 = new BufferedReader(new FileReader("test.txt"));
		String line1 = reader1.readLine();
		TripleDES.encrypt(key, System.in, System.out);
		BufferedReader reader2 = new BufferedReader(new FileReader("test.txt"));
		String line2 = reader2.readLine();
		assert(line1.equals(line2));
		
		reader1.close();
		reader2.close();
	}
	
	//tests to make sure decrypt does so consistently when using the same key
	@Test
	public void testDecrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		key = TripleDES.generateKey();
		setUpFile("test.txt", "T35tCip7eR");
		TripleDES.decrypt(key, System.in, System.out);
		BufferedReader reader1 = new BufferedReader(new FileReader("test.txt"));
		String line1 = reader1.readLine();
		TripleDES.decrypt(key, System.in, System.out);
		BufferedReader reader2 = new BufferedReader(new FileReader("test.txt"));
		String line2 = reader2.readLine();
		assert(line1.equals(line2));
		
		reader1.close();
		reader2.close();
	}
	
	//make sure the format of the key is correct
	@Test
	public void testReadKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		key = TripleDES.readKey(f);
		assert(key.getAlgorithm().equals("DESede"));
		assert(key.getFormat().equals("RAW"));
	}
	
	/***********************************************************************************/

}
