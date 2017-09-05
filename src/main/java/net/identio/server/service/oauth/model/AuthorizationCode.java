package net.identio.server.service.oauth.model;

import org.joda.time.DateTime;

public class AuthorizationCode {

    private String code;
    private String clientId;
    private String redirectUrl;
    private DateTime expirationTime;

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

    public DateTime getExpirationTime() {
        return expirationTime;
    }

    public AuthorizationCode setExpirationTime(DateTime expirationTime) {
        this.expirationTime = expirationTime;
        return this;
    }
}
