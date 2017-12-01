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

public class AuthenticationValidationResult {

    public enum ValidationStatus {
        RESPONSE, CONSENT, ERROR, CHALLENGE, AUTH
    }

    private ValidationStatus validationStatus;
    private String transactionId;
    private String errorStatus;
    private ResponseData responseData;
    private String challengeType;
    private String challengeValue;

    public static AuthenticationValidationResult response(ResponseData responseData) {
        AuthenticationValidationResult result = new AuthenticationValidationResult();
        result.validationStatus = ValidationStatus.RESPONSE;
        result.responseData = responseData;

        return result;
    }

    public static AuthenticationValidationResult consent(String transactionId) {
        AuthenticationValidationResult result = new AuthenticationValidationResult();
        result.validationStatus = ValidationStatus.CONSENT;
        result.transactionId = transactionId;

        return result;
    }

    public static AuthenticationValidationResult error(String errorStatus) {
        AuthenticationValidationResult result = new AuthenticationValidationResult();
        result.validationStatus = ValidationStatus.ERROR;
        result.errorStatus = errorStatus;

        return result;
    }

    public static AuthenticationValidationResult auth(String transactionId) {
        AuthenticationValidationResult result = new AuthenticationValidationResult();
        result.validationStatus = ValidationStatus.AUTH;
        result.transactionId = transactionId;

        return result;
    }

    public static AuthenticationValidationResult challenge(String transactionId, String challengeType, String challengeValue) {
        AuthenticationValidationResult result = new AuthenticationValidationResult();
        result.validationStatus = ValidationStatus.CHALLENGE;
        result.transactionId = transactionId;
        result.challengeType = challengeType;
        result.challengeValue = challengeValue;

        return result;
    }

    public ValidationStatus getValidationStatus() {
        return validationStatus;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public ResponseData getResponseData() {
        return responseData;
    }

    public String getChallengeType() {
        return challengeType;
    }

    public String getChallengeValue() {
        return challengeValue;
    }
}
