package net.identio.server.mvc.oauth.model;

import java.util.List;

public class ConsentRequest {

    private List<String> approvedScopes;


    public List<String> getApprovedScopes() {
        return approvedScopes;
    }

    public ConsentRequest setApprovedScopes(List<String> approvedScopes) {
        this.approvedScopes = approvedScopes;
        return this;
    }
}
