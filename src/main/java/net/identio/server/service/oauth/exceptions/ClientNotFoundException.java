package net.identio.server.service.oauth.exceptions;

public class ClientNotFoundException extends Exception {

	private static final long serialVersionUID = -3334461077718669313L;

	public ClientNotFoundException(String s) {
		super(s);
	}

	public ClientNotFoundException(String s, Throwable e) {
		super(s, e);
	}
}
