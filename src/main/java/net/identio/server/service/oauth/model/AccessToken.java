package net.identio.server.service.oauth.model;

public class AccessToken {

    private String value;
    private String type;
    private int expiresIn;
    private String scope;

    public String getValue() {
        return value;
    }

    public AccessToken setValue(String value) {
        this.value = value;
        return this;
    }

    public String getType() {
        return type;
    }

    public AccessToken setType(String type) {
        this.type = type;
        return this;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public AccessToken setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public AccessToken setScope(String scope) {
        this.scope = scope;
        return this;
    }
}
