package net.identio.server.mvc.oauth.model;

public class AccessTokenErrorResponse {

    private String error;

    public String getError() {
        return error;
    }

    public AccessTokenErrorResponse setError(String error) {
        this.error = error;
        return this;
    }
}
