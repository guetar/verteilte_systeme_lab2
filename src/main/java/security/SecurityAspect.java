package security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;

import sun.security.util.Password;

public class SecurityAspect {
	
	private final String RSA_ALGORITHM = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private final String AES_ALGORITHM = "AES/CTR/NoPadding";

	private static SecurityAspect instance = null;
	
	private SecurityAspect() {
	}
	
	public static SecurityAspect getInstance() {
		if(instance == null) instance = new SecurityAspect();
		return instance;
	}
	
	/**
	 * 
	 * @param message byte[]
	 * @return byte[]
	 */
	public byte[] encodeBase64(byte[] message) {
		Base64 decoder = new Base64();
		byte[] result = decoder.encode(message);
		return result;
	}
	
	/**
	 * 
	 * @param message String
	 * @return byte[]
	 */
	public byte[] encodeBase64String(String message) {
		return encodeBase64(message.getBytes());
	}
	
	/**
	 * 
	 * @param message String
	 * @return String
	 */
	public String decodeBase64String(String message) {
		return new String(decodeBase64(message.getBytes()));
	}
	
	/**
	 * @param message byte[]
	 * @return byte[]
	 */
	public byte[] decodeBase64(byte[] message) {
		
		Base64 decoder = new Base64();
		byte[] result = decoder.decode(message);
		
		return result;
	}
	
	/**
	 * @param size
	 * @return byte[]
	 */
	public byte[] getSecureRandomNumber(int size) {
		SecureRandom secureRandom = new SecureRandom();
		final byte[] number = new byte[size];
		secureRandom.nextBytes(number);
		
		return number;
	}
	
	/**
	 * @description erstellt einen neuen Secretkey
	 * @param keysize in bits
	 * @return SecretKey
	 */
	public SecretKey generateSecretKey(int keysize)  {
		KeyGenerator generator = null;
		try {
			generator = KeyGenerator.getInstance("AES");
			generator.init(keysize);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
				
		return generator.generateKey();
	}
	
	/**
	 * @description erstellt einen neuen Secretkey aus einem byte[]
	 * @param resource byte[]
	 * @return SecretKey
	 */
	public SecretKey generateSecretKeyOutOfByte(byte[] resource) {
		return new SecretKeySpec(resource, 0, resource.length, "AES");
	}
	
	/**
	 * 
	 * @description entschluesselt mit RSA
	 * @param text byte[]
	 * @param key PrivateKey
	 * @return byte[]
	 */
	public byte[] decryptCipherRSA(byte[] text, PrivateKey key) {
		byte[] decryptedText = null;
		
		try {
			final Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key);
			decryptedText = cipher.doFinal(text);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedText;
	}
	
	/**
	 * 
	 * @description verschluesselt mit RSA
	 * @param text String
	 * @param key PublicKey
	 * @return byte[]
	 */
	public byte[] encryptCipherRSA(String text, PublicKey key) {
		byte[] cipherText = null;
	
		try {
			final Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
		
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		} 
			
		return cipherText;
	}
	
	/**
	 * 
	 * @description entschluesselt mit AES
	 * @param text byte[]
	 * @param key secretKey
	 * @param ivparameter byte[]
	 * @return byte[]
	 */
	public byte[] decryptCipherAES(byte[] text, Key key, byte[] ivparameter) {
		byte[] decryptedText = null;
		
		IvParameterSpec ivspec = new IvParameterSpec(ivparameter);
				
		try {
			final Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
			
			decryptedText = cipher.doFinal(text);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return decryptedText;
	}
	
	/**
	 * 
	 * @description verschluesselt mit AES
	 * @param text byte[]
	 * @param key SecretKey
	 * @param ivparameter byte[]
	 * @return byte[]
	 */
	public byte[] encryptCipherAES(String text, Key key, byte[] ivparameter) {
		byte[] cipherText = null;
	
		IvParameterSpec ivspec = new IvParameterSpec(ivparameter);
		
		try {
			final Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		} 
			
		return cipherText;
	}
	
	/**
	 * 
	 * @param path relativer pfad zum Ordner in dem der Key liegt (bsp: "keys")
	 * @param username dateiname (bsp: "alice")
	 * @return erfolgreich: Publickey, andernfalls null
	 */
	public PublicKey readPublicKey(String path, String username) {
		return readPublicKey(path+"/"+username+".pub.pem");
	}
	
	/**
	 * 
	 * @param path relativer pfad zum Keyfile (bsp: "keys/user.pub.pem")
	 * @return erfolgreich: Publickey, andernfalls null
	 */
	public PublicKey readPublicKey(String path) {
		
		PublicKey publicKey = null;
		try {
			PEMReader in = new PEMReader(new FileReader(path));
			
			publicKey = (PublicKey) in.readObject();
			
			in.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			
		}
		return publicKey;
	}
	
	/**
	 * 
	 * @param path realtiver Pfad zum PrivateKeyfile ( bsp: keys/user.pem)
	 * @param password Passwort vom User
	 * @return den PrivateKey vom User wenn erfolgreich, andernfalls null
	 */
	public PrivateKey readPrivateKey(String path, String pw) {
		
		PrivateKey privateKey = null;
		
		PEMReader in;
		try {
			DefaultPasswordFinder dpf = new DefaultPasswordFinder(pw.toCharArray());
		
			PEMReader r = new PEMReader(new FileReader(new File(path)),dpf);
			KeyPair pair = ((KeyPair)r.readObject());
					
			privateKey = pair.getPrivate();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return privateKey;
	}
	
	/**
	 * 
	 * @param path relativer Pfad zu den Keys
	 * @param username User des PrivateKeys
	 * @param password Passwort vom User
	 * @return den PrivateKey vom User wenn erfolgreich, andernfalls null
	 */
	public PrivateKey readPrivateKey(String path, String username, String password) {
		return readPrivateKey(path+"/"+username+".pem", password);
	}
	
	//For a predefined password
	private static class DefaultPasswordFinder implements PasswordFinder {

        private final char [] password;

        private DefaultPasswordFinder(char [] password) {
            this.password = password;
        }

        @Override
        public char[] getPassword() {
            return password;
        }
    } 
}
