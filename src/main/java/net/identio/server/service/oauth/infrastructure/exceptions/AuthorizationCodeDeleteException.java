package net.identio.server.service.oauth.infrastructure.exceptions;

public class AuthorizationCodeDeleteException extends Exception {

    public AuthorizationCodeDeleteException(Exception e) {
        super(e);
    }
}
