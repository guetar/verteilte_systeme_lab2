package security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import message.Request;
import message.Response;
import message.request.HmacRequest;
import message.response.HmacResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import sun.security.util.Password;

public class SecurityAspect {
	
	private final String RSA_ALGORITHM = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private final String AES_ALGORITHM = "AES/CTR/NoPadding";

	private static SecurityAspect instance = null;
	
	private Base64 decoder;
	private Mac hMac;
	
	private SecurityAspect() {
		try {
			decoder = new Base64();
			hMac = Mac.getInstance("HmacSHA256");
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
		}
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
	public byte[] encryptCipherAES(byte[] text, Key key, byte[] ivparameter) {
		byte[] cipherText = null;
	
		IvParameterSpec ivspec = new IvParameterSpec(ivparameter);
		
		try {
			final Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
			cipherText = cipher.doFinal(text);
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
//			e.printStackTrace();
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
		
		PEMReader in = null;
		try {
			DefaultPasswordFinder dpf = new DefaultPasswordFinder(pw.toCharArray());
		
			PEMReader r = new PEMReader(new FileReader(new File(path)),dpf);
			KeyPair pair = ((KeyPair)r.readObject());
					
			privateKey = pair.getPrivate();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
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
	
	public Key readSharedKey(String path, boolean update) {
		try {
			byte[] keyBytes = new byte[1024];
			FileInputStream fis = new FileInputStream(path);
			fis.read(keyBytes);
			fis.close();
			
			byte[] input = Hex.decode(keyBytes);
			Key key = new SecretKeySpec(input, "HmacSHA256");
			
			if(update) updateHmac(key);
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public void updateHmac(Key hmacKey) {
		try {
			hMac.init(hmacKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean verifyHmac(HmacRequest request) {
		hMac.update(request.getRequest().toString().getBytes());
		byte[] computedHash = hMac.doFinal();
		byte[] receivedHash = Base64.decode(((HmacRequest) request).getHmac());
		return MessageDigest.isEqual(computedHash,receivedHash);
	}
	
	public boolean verifyHmac(HmacResponse response) {
		hMac.update(response.getResponse().toString().getBytes());
		byte[] computedHash = hMac.doFinal();
		byte[] receivedHash = Base64.decode(((HmacResponse) response).getHmac());
		return MessageDigest.isEqual(computedHash,receivedHash);
	}
	
	public Request hmacRequest(Request request) {
		hMac.update(request.toString().getBytes());
		byte[] hmac = Base64.encode(hMac.doFinal());
		return new HmacRequest(hmac, request);
	}
	
	public Response hmacResponse(Response response) {
		hMac.update(response.toString().getBytes());
		byte[] hmac = Base64.encode(hMac.doFinal());
		return new HmacResponse(hmac, response);
	}
	
	public String getMessageDecrypted(byte[] message, SecretKey key, byte[] ivparameter ) {
		
		byte[] cipherMessage = this.decodeBase64(message);
		
		byte[] recievedMessage = this.decryptCipherAES(cipherMessage, key, ivparameter);
		
		String result = new String(recievedMessage);
		return result;
	}
	
	public List<String> getMessageDecryptedList(byte[] message, SecretKey key, byte[] ivparameter ) {
		
		String result = this.getMessageDecrypted(message, key, ivparameter);
		String[] splitMessage = result.split(" ");
		
		List<String> list = new ArrayList<String>();
		for(String s : splitMessage) {
			list.add(s);
		}
		return list;
	}
	
	public String getMessageDecryptedAll(byte[] message, SecretKey key, byte[] ivparameter ) {
		
		List<String> list = this.getMessageDecryptedAllList(message, key, ivparameter);
		
		String result = "";
		for(int i = 0; i<list.size(); i++) {
			result += list.get(i);
			if(i<list.size()-1) result+=" ";
		}
		return result;
	}
	
	public List<String> getMessageDecryptedAllList(byte[] message, SecretKey key, byte[] ivparameter ) {
		
		List<String> list = this.getMessageDecryptedList(message, key, ivparameter);
		
		List<String> result = new ArrayList<String>();
		result.add(list.get(0));
		for(int i = 1; i<list.size(); i++) {
			
			result.add(new String(this.decodeBase64String(list.get(i))));
		}
		return result;
	}
	
	
	
	public byte[] getMessageEncrypted(String message, SecretKey key, byte[] ivparameter) {
		
		byte[] cipherMessage = this.encryptCipherAES(message.getBytes(), key, ivparameter);
		
		byte[] result = this.encodeBase64(cipherMessage);
		
		return result;
	}
}
