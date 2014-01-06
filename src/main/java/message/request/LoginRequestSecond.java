package message.request;

import java.security.PublicKey;

import javax.crypto.SecretKey;

import message.Request;
import security.SecurityAspect;

/**
 * Authenticates the client with the provided username and password.
 * <p/>
 * <b>Request</b>:<br/>
 * {@code !login &lt;username&gt; &lt;password&gt;}<br/>
 * <b>Response:</b><br/>
 * {@code !login success}<br/>
 * or<br/>
 * {@code !login wrong_credentials}
 *
 * @see message.response.LoginResponse
 */
public class LoginRequestSecond implements Request {
	private static final long serialVersionUID = -1596776158259072949L;
	
	private final String message;

	public LoginRequestSecond(byte[] proxyChallenge, SecretKey secretKey, byte[] ivparameter) {
		
		SecurityAspect secure = SecurityAspect.getInstance();
		
		String tempMessage = new String(secure.encodeBase64(proxyChallenge));
		
		byte[] cipherText = secure.encryptCipherAES(tempMessage, secretKey, ivparameter);
		
		message = new String(secure.encodeBase64(cipherText));
	}
	
	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return String.format(message);
	}
}

