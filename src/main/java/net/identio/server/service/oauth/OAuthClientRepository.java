package net.identio.server.service.oauth;

import net.identio.server.model.OAuthClient;

public interface OAuthClientRepository {

	OAuthClient getOAuthClientbyId(String cliendId);
	
}
