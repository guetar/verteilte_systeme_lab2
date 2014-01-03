package message.request;

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
	private final String password;
	
	private final String message;
	private final String challange;

	public LoginRequestFirst(String username, byte[] clientChallange, String rsa, String proxyPublicKey) {
		this.username = username;
		this.password = "";
		
		SecurityAspect secure = SecurityAspect.getInstance();
		
		challange = new String(secure.encodeBase64(clientChallange));
		
		String tempMessage = "!login " + username + " " + challange;
		message = new String(secure.encodeBase64((rsa + " " + proxyPublicKey + " " + tempMessage).getBytes()));
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}
	
	public String getChallange() {
		return challange;
	}

	@Override
	public String toString() {
		return String.format("!login %s %s", getUsername(), getChallange());
	}
}
