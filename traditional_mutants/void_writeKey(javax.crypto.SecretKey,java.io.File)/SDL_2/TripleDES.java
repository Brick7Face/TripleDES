// This is a mutant program.
// Author : ysma

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;


public class TripleDES
{

    public static  void main( java.lang.String[] args )
    {
        try {
            try {
                javax.crypto.Cipher c = Cipher.getInstance( "DESede" );
            } catch ( java.lang.Exception e ) {
                System.err.println( "Installing SunJCE provider." );
                java.security.Provider sunjce = new com.sun.crypto.provider.SunJCE();
                Security.addProvider( sunjce );
            }
            java.io.File keyfile = new java.io.File( args[1] );
            if (args[0].equals( "-g" )) {
                javax.crypto.SecretKey key = generateKey();
                writeKey( key, keyfile );
            } else {
                if (args[0].equals( "-e" )) {
                    javax.crypto.SecretKey key = readKey( keyfile );
                    encrypt( key, System.in, System.out );
                } else {
                    if (args[0].equals( "-d" )) {
                        javax.crypto.SecretKey key = readKey( keyfile );
                        decrypt( key, System.in, System.out );
                    }
                }
            }
        } catch ( java.lang.Exception e ) {
            System.err.println( e );
            System.err.println( "Usage: java " + (TripleDES.class).getName() + " -d|-e|-g <keyfile>" );
        }
    }

    public static  javax.crypto.SecretKey generateKey()
        throws java.security.NoSuchAlgorithmException
    {
        javax.crypto.KeyGenerator keygen = KeyGenerator.getInstance( "DESede" );
        return keygen.generateKey();
    }

    public static  void writeKey( javax.crypto.SecretKey key, java.io.File f )
        throws java.io.IOException, java.security.NoSuchAlgorithmException, java.security.spec.InvalidKeySpecException
    {
        javax.crypto.SecretKeyFactory keyfactory = SecretKeyFactory.getInstance( "DESede" );
        javax.crypto.spec.DESedeKeySpec keyspec = (javax.crypto.spec.DESedeKeySpec) keyfactory.getKeySpec( key, javax.crypto.spec.DESedeKeySpec.class );
        byte[] rawkey = keyspec.getKey();
        java.io.FileOutputStream out = new java.io.FileOutputStream( f );
        out.write( rawkey );
    }

    public static  javax.crypto.SecretKey readKey( java.io.File f )
        throws java.io.IOException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.spec.InvalidKeySpecException
    {
        java.io.DataInputStream in = new java.io.DataInputStream( new java.io.FileInputStream( f ) );
        byte[] rawkey = new byte[(int) f.length()];
        in.readFully( rawkey );
        in.close();
        javax.crypto.spec.DESedeKeySpec keyspec = new javax.crypto.spec.DESedeKeySpec( rawkey );
        javax.crypto.SecretKeyFactory keyfactory = SecretKeyFactory.getInstance( "DESede" );
        javax.crypto.SecretKey key = keyfactory.generateSecret( keyspec );
        return key;
    }

    public static  void encrypt( javax.crypto.SecretKey key, java.io.InputStream in, java.io.OutputStream out )
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, javax.crypto.NoSuchPaddingException, java.io.IOException
    {
        javax.crypto.Cipher cipher = Cipher.getInstance( "DESede" );
        cipher.init( Cipher.ENCRYPT_MODE, key );
        javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream( out, cipher );
        byte[] buffer = new byte[2048];
        int bytesRead;
        while ((bytesRead = in.read( buffer )) != -1) {
            cos.write( buffer, 0, bytesRead );
        }
        cos.close();
        java.util.Arrays.fill( buffer, (byte) 0 );
    }

    public static  void decrypt( javax.crypto.SecretKey key, java.io.InputStream in, java.io.OutputStream out )
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.io.IOException, javax.crypto.IllegalBlockSizeException, javax.crypto.NoSuchPaddingException, javax.crypto.BadPaddingException
    {
        javax.crypto.Cipher cipher = Cipher.getInstance( "DESede" );
        cipher.init( Cipher.DECRYPT_MODE, key );
        byte[] buffer = new byte[2048];
        int bytesRead;
        while ((bytesRead = in.read( buffer )) != -1) {
            out.write( cipher.update( buffer, 0, bytesRead ) );
        }
        out.flush();
    }

}
