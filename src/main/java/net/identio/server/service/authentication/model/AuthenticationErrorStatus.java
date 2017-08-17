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

package net.identio.server.service.authentication.model;

public class AuthenticationErrorStatus {

    public static final String INVALID_CREDENTIALS = "invalid.credentials";
    public static final String TECHNICAL_ERROR = "technical.error";
    public static final String USER_NOT_UNIQUE = "user.not.unique";
    public static final String AUTH_SAML_REJECTED = "auth.saml.rejected";
    public static final String AUTH_SAML_INVALID_RESPONSE = "auth.saml.invalid.response";
}
