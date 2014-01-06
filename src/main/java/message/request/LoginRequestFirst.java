package message.request;

import java.security.PublicKey;

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
public class LoginRequestFirst implements Request {
	private static final long serialVersionUID = -1596776158259072949L;

	private final String username;
	
	private final String message;

	public LoginRequestFirst(String username, byte[] clientChallenge, PublicKey proxyPublicKey) {
		this.username = username;
		
		SecurityAspect secure = SecurityAspect.getInstance();
		
		String tempMessage = "!login " + username + " " + new String(secure.encodeBase64(clientChallenge));
		
		assert tempMessage.matches("!login \\w+ ["+new String(clientChallenge)+"]{43}=") : "1st message";
		
		byte[] cipherText = secure.encodeBase64(secure.encryptCipherRSA(tempMessage, proxyPublicKey));
		
		message = new String(cipherText);
		
	}

	public String getUsername() {
		return username;
	}
	
	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return String.format("%s", getMessage());
	}
}

