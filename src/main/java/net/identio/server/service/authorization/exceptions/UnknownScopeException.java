package net.identio.server.service.authorization.exceptions;

public class UnknownScopeException extends Exception {

	private static final long serialVersionUID = 3426051627524438530L;

	public UnknownScopeException(String s) {
		super(s);
	}

	public UnknownScopeException(String s, Throwable e) {
		super(s, e);
	}
}
