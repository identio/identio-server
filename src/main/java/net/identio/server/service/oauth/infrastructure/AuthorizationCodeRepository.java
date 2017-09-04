package net.identio.server.service.oauth.infrastructure;

import org.joda.time.DateTime;

public interface AuthorizationCodeRepository {

    boolean save(String code, String clientId, String redirectUrl, DateTime expirationTime);
}
