package net.identio.server.mvc.oauth.model;

import net.identio.server.model.AuthorizationScope;

import java.util.List;

public class ConsentContext {

    private String audience;
    private String audienceLogo;
    private List<AuthorizationScope> requestedScopes;

    public String getAudience() {
        return audience;
    }

    public ConsentContext setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public String getAudienceLogo() {
        return audienceLogo;
    }

    public ConsentContext setAudienceLogo(String audienceLogo) {
        this.audienceLogo = audienceLogo;
        return this;
    }

    public List<AuthorizationScope> getRequestedScopes() {
        return requestedScopes;
    }

    public ConsentContext setRequestedScopes(List<AuthorizationScope> requestedScopes) {
        this.requestedScopes = requestedScopes;
        return this;
    }
}
