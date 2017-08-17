package net.identio.server.service.oauth.infrastructure;

import net.identio.server.service.oauth.model.OAuthClient;

import java.util.List;

public class OAuthClientFile {

	private List<OAuthClient> oAuthClients;

	public List<OAuthClient> getoAuthClients() {
		return oAuthClients;
	}

	public void setoAuthClients(List<OAuthClient> oAuthClients) {
		this.oAuthClients = oAuthClients;
	}

}
