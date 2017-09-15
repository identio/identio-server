package net.identio.server.service.oauth.infrastructure.exceptions;

public class AuthorizationCodeFetchException extends Exception {

    public AuthorizationCodeFetchException(Exception e) {
        super(e);
    }
}
