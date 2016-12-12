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

public enum ErrorStatus {
	OAUTH_RESPONSE_TYPE_NOT_SUPPORTED, OAUTH_CLIENT_NOT_FOUND, OAUTH_UNAUTHORIZED_CLIENT,
	AUTH_USER_ID_MISMATCH, AUTH_SAML_WRONG_AUDIENCE, AUTH_SAML_NO_RECIPIENT, AUTH_SAML_NO_DESTINATION, AUTH_SAML_WRONG_RECIPIENT_OR_DESTINATION, AUTH_SAML_CONDITIONS_NOT_MET, AUTH_SAML_INVALID_RESPONSE, AUTH_SAML_REJECTED_BY_PROXY, AUTH_SAML_NO_ASSERTION_IN_RESPONSE, AUTH_SAML_INVALID_INRESPONSETO, AUTH_USER_NOT_UNIQUE, AUTH_INVALID_CREDENTIALS, AUTH_TECHNICAL_ERROR, BUILD_AUTHENT_REQUEST_FAILED, AUTH_LEVEL_UNKNOWN, AUTH_NO_CREDENTIALS, AUTH_METHOD_UNKNOWN, AUTH_METHOD_NOT_ALLOWED, AUTHENT_REQUEST_ISSUER_UNKNOWN, AUTHENT_REQUEST_ISSUER_EMPTY, AUTHENT_REQUEST_NO_DESTINATION, AUTHENT_REQUEST_UNKNOWN_ENDPOINT, AUTHENT_REQUEST_INVALID_ENCODING, AUTHENT_REQUEST_NOT_SIGNED, AUTHENT_REQUEST_SIGNATURE_INVALID
}
