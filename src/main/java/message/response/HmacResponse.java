package message.response;

import message.Response;

public class HmacResponse implements Response {
	private final byte[] hmac;
	private final Response response;
	
	public HmacResponse(byte[] hmac, Response response) {
		this.hmac = hmac;
		this.response = response;
	}

	public byte[] getHmac() {
		return hmac;
	}

	public Response getResponse() {
		return response;
	}

	@Override
	public String toString() {
		return new String(hmac) + " " + response.toString();
	}
}
