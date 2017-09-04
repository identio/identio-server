package net.identio.server.service.oauth.infrastructure;

import net.identio.server.model.DataSource;
import org.joda.time.DateTime;

public class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private DataSource ds;

    @Override
    public boolean save(String code, String clientId, String redirectUrl, DateTime expirationTime) {
        return true;
    }
}
