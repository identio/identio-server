package net.identio.server.service.oauth.exceptions;

public class OAuthException extends Exception {

    public OAuthException(String message, Exception e) {
        super(message, e);
    }
}
