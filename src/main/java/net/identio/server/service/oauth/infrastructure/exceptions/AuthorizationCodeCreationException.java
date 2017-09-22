package net.identio.server.service.oauth.infrastructure.exceptions;

public class AuthorizationCodeCreationException extends Exception {

    public AuthorizationCodeCreationException(Exception e) {
        super(e);
    }
}
