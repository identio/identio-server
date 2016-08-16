package net.identio.server.exceptions;

public class WebSecurityException extends Exception {

	private static final long serialVersionUID = -5444195629811859215L;

	public WebSecurityException(String s) {
		super(s);
	}

	public WebSecurityException(String s, Throwable e) {
		super(s, e);
	}
}
