package net.identio.server.service.authorization.exceptions;

public class NoScopeProvidedException extends Exception {

	private static final long serialVersionUID = -7605232415378961869L;

	public NoScopeProvidedException(String s) {
		super(s);
	}

	public NoScopeProvidedException(String s, Throwable e) {
		super(s, e);
	}
}
