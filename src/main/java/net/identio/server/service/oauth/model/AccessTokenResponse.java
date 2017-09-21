package net.identio.server.service.oauth.model;

public class AccessTokenResponse {

    private String accessToken;
    private String tokenType;
    private int expiresIn;
    private String refreshToken;
    private String scope;

    public String getAccessToken() {
        return accessToken;
    }

    public AccessTokenResponse setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public String getTokenType() {
        return tokenType;
    }

    public AccessTokenResponse setTokenType(String tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public AccessTokenResponse setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public AccessTokenResponse setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public AccessTokenResponse setScope(String scope) {
        this.scope = scope;
        return this;
    }
}
