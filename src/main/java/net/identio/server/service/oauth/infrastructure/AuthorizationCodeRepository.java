package net.identio.server.service.oauth.infrastructure;

import net.identio.server.service.oauth.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.model.AuthorizationCode;

public interface AuthorizationCodeRepository {

    void save(AuthorizationCode code) throws AuthorizationCodeCreationException;
}
