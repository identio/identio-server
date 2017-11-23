/*
 * This file is part of Ident.io.
 *
 * Ident.io - A flexible authentication server
 * Copyright (c) 2017 Loeiz TANGUY
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package net.identio.server.service.transaction.model;

import net.identio.server.model.*;
import net.identio.server.service.orchestration.model.RequestParsingInfo;

import java.util.ArrayList;
import java.util.HashSet;

public class TransactionData {

    private String transactionId;
    private UserSession userSession;
    private RequestParsingInfo requestParsingInfo;
    private ArrayList<AuthLevel> targetAuthLevels;
    private HashSet<AuthMethod> targetAuthMethods = new HashSet<>();
    private TransactionState transactionState;
    private ProtocolType protocolType;

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

    public RequestParsingInfo getRequestParsingInfo() {
        return requestParsingInfo;
    }

    public void setRequestParsingInfo(RequestParsingInfo requestParsingInfo) {
        this.requestParsingInfo = requestParsingInfo;
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

    public TransactionState getState() {
        return transactionState;
    }

    public void setState(TransactionState transactionState) {
        this.transactionState = transactionState;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }
}
