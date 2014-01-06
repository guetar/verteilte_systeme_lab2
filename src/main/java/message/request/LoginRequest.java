package message.request;

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
public class LoginRequest implements Request {
	private static final long serialVersionUID = -1596776158259072949L;

	private final String username;
	private final String password;
	
	private final String message;

	public LoginRequest(String clientChallenge, byte[] proxyChallenge, SecretKey key, byte[] ivParameter) {
		this.username = "";
		this.password = "";
		
		message ="";
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	@Override
	public String toString() {
		return String.format("!login %s %s", getUsername(), getPassword());
	}
}
