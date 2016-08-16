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
package net.identio.server.model;

import java.util.ArrayList;
import java.util.HashSet;

public class TransactionData {

	private String transactionId;
	private UserSession userSession;
	private AuthRequestValidationResult arValidationResult;
	private ArrayList<AuthLevel> targetAuthLevels;
	private HashSet<AuthMethod> targetAuthMethods = new HashSet<>();
	private AuthMethod selectedAuthMethod;
	private State state;
	private String samlProxyRequestId;

	public String getTransactionId() {
		return transactionId;
	}

	public void setTransactionId(String transactionId) {
		this.transactionId = transactionId;
	}

	public UserSession getUserSession() {
		return userSession;
	}

	public void setUserSession(UserSession userSession) {
		this.userSession = userSession;
	}

	public AuthRequestValidationResult getArValidationResult() {
		return arValidationResult;
	}

	public void setArValidationResult(AuthRequestValidationResult arValidationResult) {
		this.arValidationResult = arValidationResult;
	}

	public ArrayList<AuthLevel> getTargetAuthLevels() {
		return targetAuthLevels;
	}

	public void setTargetAuthLevels(ArrayList<AuthLevel> targetAuthLevels) {
		this.targetAuthLevels = targetAuthLevels;
	}

	public HashSet<AuthMethod> getTargetAuthMethods() {
		return targetAuthMethods;
	}

	public void setTargetAuthMethods(HashSet<AuthMethod> targetAuthMethods) {
		this.targetAuthMethods = targetAuthMethods;
	}

	public AuthMethod getSelectedAuthMethod() {
		return selectedAuthMethod;
	}

	public void setSelectedAuthMethod(AuthMethod selectedAuthMethod) {
		this.selectedAuthMethod = selectedAuthMethod;
	}

	public State getState() {
		return state;
	}

	public void setState(State state) {
		this.state = state;
	}

	public String getSamlProxyRequestId() {
		return samlProxyRequestId;
	}

	public void setSamlProxyRequestId(String samlProxyRequestId) {
		this.samlProxyRequestId = samlProxyRequestId;
	}
}
