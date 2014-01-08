package message.response;

import java.security.Key;
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
public class LogoutResponse implements Response {
	private static final long serialVersionUID = 3134831924072300109L;

	private final byte[] message;

	public LogoutResponse(String message, Key key, byte[] ivparameter) {
		
		SecurityAspect secure = SecurityAspect.getInstance();
		
		String tempMessage = "!credits " + new String(secure.encodeBase64String(message));
		
		this.message = secure.encodeBase64(secure.encryptCipherAES(tempMessage.getBytes(), key, ivparameter));
	}

	public byte[] getMessage() {
		return message;
	}

	@Override
	public String toString() {
		return new String(message);
	}
}
