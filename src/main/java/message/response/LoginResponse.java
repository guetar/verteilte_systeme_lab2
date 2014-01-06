package message.response;

import java.security.PublicKey;

import javax.crypto.SecretKey;

import security.SecurityAspect;
import message.Response;

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
 * @see message.request.LoginRequest
 */
public class LoginResponse implements Response {
	private static final long serialVersionUID = 3134831924072300109L;

	private final byte[] message;
	private final String tempMessage;

	public LoginResponse(PublicKey userPublicKey, byte[] clientChallenge, byte[] proxyChallenge, SecretKey key, byte[] ivParameter) {
				
		SecurityAspect secure = SecurityAspect.getInstance();
		
		String proxyChallengeString = new String(secure.encodeBase64(proxyChallenge));
		
		String keyString = new String(secure.encodeBase64(key.getEncoded()));
		
		String ivParameterString = new String(secure.encodeBase64(ivParameter));
		
		tempMessage = "!ok " + clientChallenge + " " + proxyChallengeString + " " + keyString + " " +  ivParameterString;
		
		byte[] cipherText = secure.encryptCipherRSA(tempMessage, userPublicKey);
		
		message = secure.encodeBase64(cipherText);
	}

	public byte[] getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return tempMessage;
	}
}
