/*
 This file is part of Ident.io

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
package net.identio.server.model.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import net.identio.server.model.ErrorStatus;
import net.identio.server.model.State;

@JsonInclude(Include.NON_NULL)
public class AuthSubmitResponse {

	private State state;
	private ErrorStatus errorStatus;
	private String destinationUrl;
	private String relayState;
	private String samlResponse;
	private String challengeType;
	private String challengeValue;

	public State getState() {
		return state;
	}

	public AuthSubmitResponse setState(State state) {
		this.state = state;
		return this;
	}

	public ErrorStatus getErrorStatus() {
		return errorStatus;
	}

	public AuthSubmitResponse setErrorStatus(ErrorStatus errorStatus) {
		this.errorStatus = errorStatus;
		return this;
	}

	public String getDestinationUrl() {
		return destinationUrl;
	}

	public AuthSubmitResponse setDestinationUrl(String destinationUrl) {
		this.destinationUrl = destinationUrl;
		return this;
	}

	public String getRelayState() {
		return relayState;
	}

	public AuthSubmitResponse setRelayState(String relayState) {
		this.relayState = relayState;
		return this;
	}

	public String getSamlResponse() {
		return samlResponse;
	}

	public AuthSubmitResponse setSamlResponse(String samlResponse) {
		this.samlResponse = samlResponse;
		return this;
	}

	public String getChallengeType() {
		return challengeType;
	}

	public AuthSubmitResponse setChallengeType(String challengeType) {
		this.challengeType = challengeType;
		return this;
	}

	public String getChallengeValue() {
		return challengeValue;
	}

	public AuthSubmitResponse setChallengeValue(String challengeValue) {
		this.challengeValue = challengeValue;
		return this;
	}

}
