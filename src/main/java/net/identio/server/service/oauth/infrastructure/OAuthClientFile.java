package net.identio.server.service.oauth.infrastructure;

import java.util.List;

import net.identio.server.model.OAuthClient;

public class OAuthClientFile {

	private List<OAuthClient> oauthClients;

	public List<OAuthClient> getOauthClients() {
		return oauthClients;
	}

	public void setOauthClients(List<OAuthClient> oauthClients) {
		this.oauthClients = oauthClients;
	}
}
