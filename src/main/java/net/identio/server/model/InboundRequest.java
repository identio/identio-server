/*
 This file is part of Ident.io.

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.model;

public class InboundRequest {

	private RequestType type = RequestType.SAML;
	private String binding;
	private String serializedRequest;
	private String signatureValue;
	private String signedInfo;
	private String signatureAlgorithm;
	private String relayState;

	public InboundRequest(String binding, String serializedRequest, String signatureValue, String signedInfo,
			String signatureAlgorithm, String relayState) {
		this.binding = binding;
		this.serializedRequest = serializedRequest;
		this.signatureValue = signatureValue;
		this.signedInfo = signedInfo;
		this.signatureAlgorithm = signatureAlgorithm;
		this.relayState = relayState;
	}

	public RequestType getType() {
		return type;
	}

	public void setType(RequestType type) {
		this.type = type;
	}

	public String getBinding() {
		return binding;
	}

	public void setBinding(String binding) {
		this.binding = binding;
	}

	public String getSerializedRequest() {
		return serializedRequest;
	}

	public void setSerializedRequest(String serializedRequest) {
		this.serializedRequest = serializedRequest;
	}

	public String getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(String signatureValue) {
		this.signatureValue = signatureValue;
	}

	public String getSignedInfo() {
		return signedInfo;
	}

	public void setSignedInfo(String signedInfo) {
		this.signedInfo = signedInfo;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getRelayState() {
		return relayState;
	}

	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}

}
