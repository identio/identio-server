package net.identio.server.service.oauth.model;

public class AuthorizationRequest {

    private String grantType;

    private String code;

    private String redirectUri;

    public String getGrantType() {
        return grantType;
    }

    public AuthorizationRequest setGrantType(String grantType) {
        this.grantType = grantType;
        return this;
    }

    public String getCode() {
        return code;
    }

    public AuthorizationRequest setCode(String code) {
        this.code = code;
        return this;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public AuthorizationRequest setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }
}
