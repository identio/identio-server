package net.identio.server.service.oauth.exceptions;

public class AuthorizationCodeCreationException extends Exception {

    public AuthorizationCodeCreationException(Exception e) {
        super(e);
    }
}
