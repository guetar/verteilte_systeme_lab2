package message.request;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.List;

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
public class EncryptedRequest implements Request {
	private static final long serialVersionUID = -1596776158259072949L;

	private final byte[] message;

	public EncryptedRequest(Request request, SecretKey key, byte[] ivparameter) throws IOException {

		SecurityAspect secure = SecurityAspect.getInstance();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(request);
		  message = secure.encodeBase64(secure.encryptCipherAES(bos.toByteArray(), key, ivparameter));
		} finally {
			if(out!=null && bos!= null) {
				out.close();
			    bos.close();
			}
		}
	}
	
	public Request getRequest(SecretKey key, byte[] ivparameter) throws IOException, ClassNotFoundException {
		SecurityAspect secure = SecurityAspect.getInstance();
		Request request = null;
		byte[] encryptedMessage = secure.decryptCipherAES(secure.decodeBase64(message), key, ivparameter);
		
		ByteArrayInputStream bis = new ByteArrayInputStream(encryptedMessage);
		ObjectInput in = null;
		try {
		  in = new ObjectInputStream(bis);
		   request = (Request) in.readObject(); 
		} finally {
		    bis.close();
		    if (in != null) {
		      in.close();
		    }
		}
		
		return request;
	}

	@Override
	public String toString() {
		return "";
	}
}
