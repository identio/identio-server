package net.identio.server.model;

import java.util.List;

public class OAuthInboundRequest implements InboundRequest {

	private String clientId;
	private String responseType;
	private String redirectUri;
	private List<String> scopes;
	private String state;

	public OAuthInboundRequest(String clientId, String responseType, String redirectUri, List<String> scopes,
			String state) {

		this.clientId = clientId;
		this.responseType = responseType;
		this.redirectUri = redirectUri;
		this.scopes = scopes;
		this.state = state;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getResponseType() {
		return responseType;
	}

	public void setResponseType(String responseType) {
		this.responseType = responseType;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public List<String> getScopes() {
		return scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}
}
