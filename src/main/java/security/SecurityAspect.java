package security;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import com.sun.xml.internal.messaging.saaj.util.Base64;

public class SecurityAspect {

	private static SecurityAspect instance = null;
	
	private SecurityAspect() {
		
	}
	
	public static SecurityAspect getInstance() {
		if(instance == null) instance = new SecurityAspect();
		return instance;
	}
	
	public byte[] encodeBase64(byte[] message) {
		byte[] result = Base64.encode(message);
		
		return result;
	}
	
	public String decodeBase64String(String message) {
		
		Base64 decoder = new Base64();
		String result = decoder.base64Decode(message);
		
		return result;
	}
	
	public byte[] decodeBase64Byte(byte[] message) {
		
		Base64 decoder = new Base64();
		byte[] result = decoder.decode(message);
		
		return result;
	}
	
	public byte[] getSecureRandomNumber(int size) {
		SecureRandom secureRandom = new SecureRandom();
		final byte[] number = new byte[size];
		secureRandom.nextBytes(number);
		
		return number;
	}
	
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
		
		if(generator==null) return null;
		
		return generator.generateKey();
	}	
	
	public Cipher initCipherDecrypt(Key key) {
		Cipher crypt = null;
		try {
			crypt = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
			
			crypt.init(Cipher.DECRYPT_MODE, key);
			
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(crypt == null) return null;
		
		return crypt;
	}
	public Cipher initCipherEncrypt(Key key) {
		Cipher crypt = null;
		try {
			crypt = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
			
			crypt.init(Cipher.ENCRYPT_MODE, key);
			
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(crypt == null) return null;
		
		return crypt;
	}
}
