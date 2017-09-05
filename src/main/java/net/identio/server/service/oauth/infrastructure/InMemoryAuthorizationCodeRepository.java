package net.identio.server.service.oauth.infrastructure;

import net.identio.server.service.oauth.model.AuthorizationCode;

public class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository {

    @Override
    public void save(AuthorizationCode code) {
    }
}
