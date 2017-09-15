package net.identio.server.service.oauth.infrastructure;

import net.identio.server.service.oauth.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeFetchException;
import net.identio.server.service.oauth.model.AuthorizationCode;

import java.util.Optional;

public interface AuthorizationCodeRepository {

    void save(AuthorizationCode code) throws AuthorizationCodeCreationException;

    Optional<AuthorizationCode> getAuthorizationCodeByValue(String code) throws AuthorizationCodeFetchException;

    void delete(AuthorizationCode code) throws AuthorizationCodeDeleteException;
}
