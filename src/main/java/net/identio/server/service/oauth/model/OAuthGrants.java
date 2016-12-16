package net.identio.server.service.oauth.model;

public enum OAuthGrants {
	IMPLICIT("implicit"), AUTHORIZATION_CODE("authorization_code");
	
	private String name;
	
	OAuthGrants(String name) {
		this.name = name;
	}
	
	public String toString() {
		return this.name;
	}
}
