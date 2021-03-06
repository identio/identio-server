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

@JsonInclude(Include.NON_NULL)
public class AuthSubmitRequest {

    private String method;
    private String login;
    private String password;
    private String challengeResponse;

    public String getMethod() {
        return method;
    }

    public AuthSubmitRequest setMethod(String method) {
        this.method = method;
        return this;
    }

    public String getLogin() {
        return login;
    }

    public AuthSubmitRequest setLogin(String login) {
        this.login = login;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public AuthSubmitRequest setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getChallengeResponse() {
        return challengeResponse;
    }

    public AuthSubmitRequest setChallengeResponse(String challengeResponse) {
        this.challengeResponse = challengeResponse;
        return this;
    }

}
