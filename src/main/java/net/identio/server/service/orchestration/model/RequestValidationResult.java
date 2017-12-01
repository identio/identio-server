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

public class RequestValidationResult {

    public enum ValidationStatus {
        RESPONSE, CONSENT, ERROR, AUTH
    }

    private ValidationStatus validationStatus;
    private String errorStatus;
    private ResponseData responseData;
    private String transactionId;
    private String sessionId;

    public static RequestValidationResult response(ResponseData responseData) {
        RequestValidationResult result = new RequestValidationResult();
        result.validationStatus = ValidationStatus.RESPONSE;
        result.responseData = responseData;

        return result;
    }

    public static RequestValidationResult consent(String transactionId, String sessionId) {
        RequestValidationResult result = new RequestValidationResult();
        result.validationStatus = ValidationStatus.CONSENT;
        result.transactionId = transactionId;
        result.sessionId = sessionId;

        return result;
    }

    public static RequestValidationResult error(String errorStatus) {
        RequestValidationResult result = new RequestValidationResult();
        result.validationStatus = ValidationStatus.ERROR;
        result.errorStatus = errorStatus;

        return result;
    }

    public static RequestValidationResult auth(String transactionId, String sessionId) {
        RequestValidationResult result = new RequestValidationResult();
        result.validationStatus = ValidationStatus.AUTH;
        result.transactionId = transactionId;
        result.sessionId = sessionId;

        return result;
    }

    public ValidationStatus getValidationStatus() {
        return validationStatus;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public ResponseData getResponseData() {
        return responseData;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public String getSessionId() {
        return sessionId;
    }
}
