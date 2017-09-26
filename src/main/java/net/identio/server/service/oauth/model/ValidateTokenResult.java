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

package net.identio.server.service.oauth.model;

public class ValidateTokenResult {

    private ValidateTokenStatus status;
    private String errorStatus;
    private AccessTokenResponse response;

    public ValidateTokenStatus getStatus() {
        return status;
    }

    public ValidateTokenResult setStatus(ValidateTokenStatus status) {
        this.status = status;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public ValidateTokenResult setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    public AccessTokenResponse getResponse() {
        return response;
    }

    public ValidateTokenResult setResponse(AccessTokenResponse response) {
        this.response = response;
        return this;
    }
}
