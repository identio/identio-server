package net.identio.server.model;

public enum OAuthResponseType {
	CODE("code"), TOKEN("token");
	
	private String name;
	
	OAuthResponseType(String name) {
		this.name = name;
	}
	
	public String toString() {
		return this.name;
	}
}
