package net.identio.server.service.oauth.model;

public class AuthorizationCode {

    private String code;
    private String clientId;
    private String redirectUrl;
    private long expirationTime;
    private String scope;
    private String userId;

    public String getCode() {
        return code;
    }

    public AuthorizationCode setCode(String code) {
        this.code = code;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public AuthorizationCode setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public AuthorizationCode setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
        return this;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public AuthorizationCode setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public AuthorizationCode setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public AuthorizationCode setUserId(String userId) {
        this.userId = userId;
        return this;
    }
}

