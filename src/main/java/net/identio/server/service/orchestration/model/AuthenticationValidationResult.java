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
package net.identio.server.service.orchestration.model;

import net.identio.server.model.ProtocolType;

public class AuthenticationValidationResult {

    private ValidationStatus validationStatus;
    private String errorStatus;
    private ResponseData responseData;
    private ProtocolType protocolType;
    private String challengeType;
    private String challengeValue;

    public ValidationStatus getValidationStatus() {
        return validationStatus;
    }

    public AuthenticationValidationResult setValidationStatus(ValidationStatus state) {
        this.validationStatus = state;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public AuthenticationValidationResult setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    public ResponseData getResponseData() {
        return responseData;
    }

    public AuthenticationValidationResult setResponseData(ResponseData responseData) {
        this.responseData = responseData;
        return this;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public AuthenticationValidationResult setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
        return this;
    }

    public String getChallengeType() {
        return challengeType;
    }

    public AuthenticationValidationResult setChallengeType(String challengeType) {
        this.challengeType = challengeType;
        return this;
    }

    public String getChallengeValue() {
        return challengeValue;
    }

    public AuthenticationValidationResult setChallengeValue(String challengeValue) {
        this.challengeValue = challengeValue;
        return this;
    }
}
