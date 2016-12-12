package net.identio.server.service.oauth;

import net.identio.server.model.OAuthClient;
import net.identio.server.service.oauth.exceptions.ClientNotFoundException;

public interface OAuthClientRepository {

	OAuthClient getOAuthClientbyId(String cliendId) throws ClientNotFoundException;
	
}
