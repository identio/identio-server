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
package net.identio.server.mvc.common.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import net.identio.server.service.orchestration.model.ResponseData;

@JsonInclude(Include.NON_NULL)
public class AuthSubmitResponse {

    private ApiResponseStatus status;
    private String errorStatus;
    private ResponseData responseData;
    private String challengeType;
    private String challengeValue;

    public ApiResponseStatus getStatus() {
        return status;
    }

    public AuthSubmitResponse setStatus(ApiResponseStatus status) {
        this.status = status;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public AuthSubmitResponse setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    public ResponseData getResponseData() {
        return responseData;
    }

    public AuthSubmitResponse setResponseData(ResponseData responseData) {
        this.responseData = responseData;
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
