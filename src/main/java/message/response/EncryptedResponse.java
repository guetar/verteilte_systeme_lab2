package message.response;

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
import message.Response;
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
public class EncryptedResponse implements Response {
	private static final long serialVersionUID = -1596776158259072949L;

	private final byte[] message;

	public EncryptedResponse(Response response, SecretKey key, byte[] ivparameter) throws IOException {

		SecurityAspect secure = SecurityAspect.getInstance();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(response);
		  message = secure.encodeBase64(secure.encryptCipherAES(bos.toByteArray(), key, ivparameter));
		} finally {
			if(out!=null && bos!= null) {
				out.close();
			    bos.close();
			}
		}
	}
	
	public Response getResponse(SecretKey key, byte[] ivparameter) throws IOException, ClassNotFoundException {
		SecurityAspect secure = SecurityAspect.getInstance();
		Response response = null;
		byte[] encryptedMessage = secure.decryptCipherAES(secure.decodeBase64(message), key, ivparameter);
		
		ByteArrayInputStream bis = new ByteArrayInputStream(encryptedMessage);
		ObjectInput in = null;
		try {
		  in = new ObjectInputStream(bis);
		   response = (Response) in.readObject(); 
		} finally {
		    bis.close();
		    if (in != null) {
		      in.close();
		    }
		}
		
		return response;
	}

	@Override
	public String toString() {
		return "";
	}
}
