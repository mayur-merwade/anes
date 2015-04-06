package securecloudstorageuser.encryption;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.Cipher;


import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.*;

import sun.misc.*;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * <p>Title: RSAEncryptUtil</p>
 * <p>Description: Utility class that helps encrypt and decrypt strings using RSA algorithm</p>
 * @author Aviran Mordo http://aviran.mordos.com
 * @version 1.0
 */
public class RSAEncryptUtil
{
    protected static final String ALGORITHM = "RSA";

    private RSAEncryptUtil()
    {
    }

    /**
     * Init java security to add BouncyCastle as an RSA provider
     */
    public static void init()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generate key which contains a pair of privae and public key using 1024 bytes
     * @return key pair
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKey() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        return key;
    }


    /**
     * Encrypt a text using public key.
     * @param text The original unencrypted text
     * @param key The public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    public static byte[] encrypt(byte[] text, PublicKey key) throws Exception
    {
        byte[] cipherText = null;
        try
        {
             //JOptionPane.showMessageDialog(null,"Hello");
            //
            // get an RSA cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // encrypt the plaintext using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text);
        }
        catch (Exception e)
        {
            throw e;
        }
        return cipherText;
    }
    
    
    
    
    
    /* New addition */
    private static byte[] append(byte[] prefix, byte[] suffix){
	byte[] toReturn = new byte[prefix.length + suffix.length];
	for (int i=0; i< prefix.length; i++){
		toReturn[i] = prefix[i];
	}
	for (int i=0; i< suffix.length; i++){
		toReturn[i+prefix.length] = suffix[i];
	}
	return toReturn;
}
    
    
    
    
    
    /* New addition */
    private static byte[] blockCipher(byte[] bytes, int mode,PublicKey key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
	// string initialize 2 buffers.
	// scrambled will hold intermediate results
	byte[] scrambled = new byte[0];

         Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         cipher.init(Cipher.ENCRYPT_MODE, key);
	// toReturn will hold the total result
	byte[] toReturn = new byte[0];
	// if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
	int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;

	// another buffer. this one will hold the bytes that have to be modified in this step
	byte[] buffer = new byte[length];

	for (int i=0; i< bytes.length; i++){

		// if we filled our buffer array we have our block ready for de- or encryption
		if ((i > 0) && (i % length == 0)){
			//execute the operation
			scrambled = cipher.doFinal(buffer);
			// add the result to our total result.
			toReturn = append(toReturn,scrambled);
			// here we calculate the length of the next buffer required
			int newlength = length;

			// if newlength would be longer than remaining bytes in the bytes array we shorten it.
			if (i + length > bytes.length) {
				 newlength = bytes.length - i;
			}
			// clean the buffer array
			buffer = new byte[newlength];
		}
		// copy byte into our buffer.
		buffer[i%length] = bytes[i];
	}

	// this step is needed if we had a trailing buffer. should only happen when encrypting.
	// example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
	scrambled = cipher.doFinal(buffer);

	// final step before we can return the modified data.
	toReturn = append(toReturn,scrambled);

	return toReturn;
}
    
    
    

    /*changed */
    
    /**
     * Encrypt a text using public key. The result is enctypted BASE64 encoded text
     * @param text The original unencrypted text
     * @param key The public key
     * @return Encrypted text encoded as BASE64
     * @throws java.lang.Exception
     */
    /*public static String encrypt(String text, PublicKey key) throws Exception
    {
        String encryptedText;
        try
        {
            byte[] cipherText = encrypt(text.getBytes("UTF8"),key);
            encryptedText = encodeBASE64(cipherText);
        }
        catch (Exception e)
        {
            throw e;
        }
        return encryptedText;
    } */
    
    /* new encrypt */
    public static String encrypt(String plaintext,PublicKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, key);
	byte[] bytes = plaintext.getBytes("UTF-8");

	byte[] encrypted = blockCipher(bytes,Cipher.ENCRYPT_MODE,key);

	char[] encryptedTranspherable = Hex.encodeHex(encrypted);
	return new String(encryptedTranspherable);
}
    
    
    
    
    
    
    

    /**
     * Decrypt text using private key
     * @param text The encrypted text
     * @param key The private key
     * @return The unencrypted text
     * @throws java.lang.Exception
     */
    public static byte[] decrypt(byte[] text, PrivateKey key) throws Exception
    {
        byte[] dectyptedText = null;
        try
        {
            // decrypt the text using the private key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);
        }
        catch (Exception e)
        {
            throw e;
        }
        return dectyptedText;

    }

    /**
     * Decrypt BASE64 encoded text using private key
     * @param text The encrypted text, encoded as BASE64
     * @param key The private key
     * @return The unencrypted text encoded as UTF8
     * @throws java.lang.Exception
     */
    public static String decrypt(String text, PrivateKey key) throws Exception
    {
        String result;
        try
        {
            // decrypt the text using the private key
            byte[] dectyptedText = decrypt(decodeBASE64(text),key);
            result = new String(dectyptedText, "UTF8");
        }
        catch (Exception e)
        {
            throw e;
        }
        return result;

    }

    /**
     * Convert a Key to string encoded as BASE64
     * @param key The key (private or public)
     * @return A string representation of the key
     */
    public static String getKeyAsString(Key key)
    {
        // Get the bytes of the key
        byte[] keyBytes = key.getEncoded();
        // Convert key to BASE64 encoded string
        BASE64Encoder b64 = new BASE64Encoder();
        return b64.encode(keyBytes);
    }

    /**
     * Generates Private Key from BASE64 encoded string
     * @param key BASE64 encoded string which represents the key
     * @return The PrivateKey
     * @throws java.lang.Exception
     */
    public static PrivateKey getPrivateKeyFromString(String key) throws Exception
    {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        BASE64Decoder b64 = new BASE64Decoder();
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(b64.decodeBuffer(key));
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    /**
     * Generates Public Key from BASE64 encoded string
     * @param key BASE64 encoded string which represents the key
     * @return The PublicKey
     * @throws java.lang.Exception
     */
    public static PublicKey getPublicKeyFromString(String key) throws Exception
    {
        BASE64Decoder b64 = new BASE64Decoder();
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(b64.decodeBuffer(key));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    /**
     * Encode bytes array to BASE64 string
     * @param bytes
     * @return Encoded string
     */
    private static String encodeBASE64(byte[] bytes)
    {
        BASE64Encoder b64 = new BASE64Encoder();
        return b64.encode(bytes);
    }

    /**
     * Decode BASE64 encoded string to bytes array
     * @param text The string
     * @return Bytes array
     * @throws IOException
     */
    private static byte[] decodeBASE64(String text) throws IOException
    {
        BASE64Decoder b64 = new BASE64Decoder();
        return b64.decodeBuffer(text);
    }

    /**
     * Encrypt file using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    public static void encryptFile(String srcFileName, String destFileName, PublicKey key) throws Exception
    {
        encryptDecryptFile(srcFileName,destFileName, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * Decrypt file using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    public static void decryptFile(String srcFileName, String destFileName, PrivateKey key) throws Exception
    {
        encryptDecryptFile(srcFileName,destFileName, key, Cipher.DECRYPT_MODE);
    }

    /**
     * Encrypt and Decrypt files using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    public static void encryptDecryptFile(String srcFileName, String destFileName, Key key, int cipherMode) throws Exception
    {
        OutputStream outputWriter = null;
        InputStream inputReader = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            String textLine = null;
            //RSA encryption data size limitations are slightly less than the key modulus size,
            //depending on the actual padding scheme used (e.g. with 1024 bit (128 byte) RSA key,
            //the size limit is 117 bytes for PKCS#1 v 1.5 padding. (http://www.jensign.com/JavaScience/dotnet/RSAEncrypt/)
            byte[] buf = cipherMode == Cipher.ENCRYPT_MODE? new byte[100] : new byte[128];
            int bufl;
            // init the Cipher object for Encryption...
            cipher.init(cipherMode, key);

            // start FileIO
            outputWriter = new FileOutputStream(destFileName);
            inputReader = new FileInputStream(srcFileName);
            
            
            StringBuffer outputBuffer = new StringBuffer();
            while ( (bufl = inputReader.read(buf)) != -1)
            {
                byte[] encText = null;
                if (cipherMode == Cipher.ENCRYPT_MODE)
                {
                      encText = encrypt(copyBytes(buf,bufl),(PublicKey)key);
                }
                else
                {
                    encText = decrypt(copyBytes(buf,bufl),(PrivateKey)key);
                }
                outputWriter.write(encText);
                //outputBuffer.append(encText);
            }
           // outputWriter.write(outputBuffer.toString().getBytes());
            outputWriter.flush();

        }
        catch (Exception e)
        {
            throw e;
        }
        finally
        {
            try
            {
                if (outputWriter != null)
                {
                    outputWriter.close();
                }
                if (inputReader != null)
                {
                    inputReader.close();
                }
            }
            catch (Exception e)
            {
                // do nothing...
            } // end of inner try, catch (Exception)...
        }
    }

    public static byte[] copyBytes(byte[] arr, int length)
    {
        byte[] newArr = null;
        if (arr.length == length)
        {
        	System.out.println("---if----");
            newArr = arr;
        }
        else
        {
        	System.out.println("---else----");
            newArr = new byte[length];
            for (int i = 0; i < length; i++)            {
                newArr[i] = (byte) arr[i];
            }
        }
        return newArr;
    }

}

