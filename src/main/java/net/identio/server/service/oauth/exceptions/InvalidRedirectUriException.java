package net.identio.server.service.oauth.exceptions;

public class InvalidRedirectUriException extends Exception {

	private static final long serialVersionUID = -3334461077718669313L;

	public InvalidRedirectUriException(String s) {
		super(s);
	}

	public InvalidRedirectUriException(String s, Throwable e) {
		super(s, e);
	}
}
