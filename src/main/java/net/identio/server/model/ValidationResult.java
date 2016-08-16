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

public class ValidationResult {

	private State state;
	private ErrorStatus errorStatus;
	private String responseData;
	private AuthRequestValidationResult arValidationResult;
	private String transactionId;
	private String sessionId;
	private String challengeType;
	private String challengeValue;

	public State getState() {
		return state;
	}

	public ErrorStatus getErrorStatus() {
		return errorStatus;
	}

	public void setErrorStatus(ErrorStatus errorStatus) {
		this.errorStatus = errorStatus;
	}

	public void setState(State state) {
		this.state = state;
	}

	public String getResponseData() {
		return responseData;
	}

	public void setResponseData(String responseData) {
		this.responseData = responseData;
	}

	public AuthRequestValidationResult getArValidationResult() {
		return arValidationResult;
	}

	public void setArValidationResult(AuthRequestValidationResult arValidationResult) {
		this.arValidationResult = arValidationResult;
	}

	public String getTransactionId() {
		return transactionId;
	}

	public void setTransactionId(String transactionId) {
		this.transactionId = transactionId;
	}

	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public String getChallengeType() {
		return challengeType;
	}

	public void setChallengeType(String challengeType) {
		this.challengeType = challengeType;
	}

	public String getChallengeValue() {
		return challengeValue;
	}

	public void setChallengeValue(String challengeValue) {
		this.challengeValue = challengeValue;
	}

}
