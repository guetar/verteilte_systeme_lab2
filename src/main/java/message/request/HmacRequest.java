package message.request;

import message.Request;

public class HmacRequest implements Request {
	private final byte[] hmac;
	private final Request request;

	public HmacRequest(byte[] hmac, Request request) {
		this.hmac = hmac;
		this.request = request;
	}

	public byte[] getHmac() {
		return hmac;
	}
	
	public Request getRequest() {
		return request;
	}

	@Override
	public String toString() {
		return new String(hmac) + " " + request.toString();
	}
}
