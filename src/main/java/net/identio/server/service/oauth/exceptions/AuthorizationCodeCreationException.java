package net.identio.server.service.oauth.exceptions;

public class AuthorizationCodeCreationException extends Exception {

    public AuthorizationCodeCreationException(String message, Exception e) {
        super(message, e);
    }
}
