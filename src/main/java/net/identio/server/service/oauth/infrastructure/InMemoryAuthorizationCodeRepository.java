package net.identio.server.service.oauth.infrastructure;

import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.model.AuthorizationCode;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.Optional;

public class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository {

    @Override
    public void save(AuthorizationCode code) {
        // TODO
        throw new NotImplementedException();
    }

    @Override
    public Optional<AuthorizationCode> getAuthorizationCodeByValue(String code) {
        // TODO
        throw new NotImplementedException();
    }

    @Override
    public void delete(AuthorizationCode code) throws AuthorizationCodeDeleteException {
        // TODO
        throw new NotImplementedException();
    }
}
