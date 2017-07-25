package net.identio.server.service.oauth.infrastructure;

import java.util.List;

import net.identio.server.model.OAuthClient;

public class OAuthClientFile {

	private List<OAuthClient> oAuthClients;

	public List<OAuthClient> getoAuthClients() {
		return oAuthClients;
	}

	public void setoAuthClients(List<OAuthClient> oAuthClients) {
		this.oAuthClients = oAuthClients;
	}

}
