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
package net.identio.server.service.oauth;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.ErrorStatus;
import net.identio.server.model.OAuthClient;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.model.ProtocolType;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.UserSession;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.exceptions.ClientNotFoundException;
import net.identio.server.service.oauth.exceptions.InvalidRedirectUriException;
import net.identio.server.service.oauth.model.OAuthGrants;
import net.identio.server.service.oauth.model.OAuthResponseType;

@Service
public class OAuthService {

	private static final Logger LOG = LoggerFactory.getLogger(OAuthService.class);

	@Autowired
	private OAuthClientRepository clientRepository;
	@Autowired
	private AuthorizationService authorizationService;

	private ConfigurationService configurationService;

	private RSAKey signingKey;

	@Autowired
	public OAuthService(ConfigurationService configurationService) throws InitializationException {
		this.configurationService = configurationService;

		// Cache signing certificate
		try (FileInputStream fis = new FileInputStream(
				configurationService.getConfiguration().getGlobalConfiguration().getSignatureKeystorePath())) {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, configurationService.getConfiguration().getGlobalConfiguration().getSignatureKeystorePassword()
					.toCharArray());

			Enumeration<String> aliases = ks.aliases();

			if (aliases == null || !aliases.hasMoreElements()) {
				throw new InitializationException("Keystore doesn't contain a certificate");
			}

			String alias = aliases.nextElement();

			KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
					new KeyStore.PasswordProtection(configurationService.getConfiguration().getGlobalConfiguration()
							.getSignatureKeystorePassword().toCharArray()));

			signingKey = (RSAKey) keyEntry.getPrivateKey();

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableEntryException ex) {
			throw new InitializationException("Could not initialize OAuth Service", ex);
		}
	}

	public AuthRequestValidationResult validateAuthentRequest(OAuthInboundRequest request)
			throws ClientNotFoundException, InvalidRedirectUriException {

		AuthRequestValidationResult result = new AuthRequestValidationResult();

		// Fetch client
		OAuthClient client = clientRepository.getOAuthClientbyId(request.getClientId());

		// Verify redirectUri
		checkRedirectUri(client, request.getRedirectUri());

		// Validate response type value
		if (!checkValidResponseTypes(request.getResponseType())) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_RESPONSE_TYPE_NOT_SUPPORTED);
		}

		// Validate scope value
		List<AuthorizationScope> scopes;
		try {
			scopes = authorizationService.getScopes(request.getScopes());
		} catch (UnknownScopeException | NoScopeProvidedException e) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_INVALID_SCOPE);
		}

		// Validate client authorization regarding allowed scopes and response
		// types
		if (!checkClientAuthorization(client, request.getResponseType(), request.getScopes())) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_UNAUTHORIZED_CLIENT);
		}

		result.setSuccess(true).setSourceApplicationName(client.getName()).setResponseUrl(request.getRedirectUri())
				.setProtocolType(ProtocolType.OAUTH).setRelayState(request.getState()).setRequestedScopes(scopes)
				.setResponseType(request.getResponseType());

		return result;
	}

	public String generateSuccessResponse(AuthRequestValidationResult result, UserSession userSession) {

		// http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600
		StringBuilder responseBuilder = new StringBuilder();

		responseBuilder.append(result.getResponseUrl()).append("#");

		// Determine expiration time of the authorization
		int expirationTime = -1;
		for (AuthorizationScope scope : result.getRequestedScopes()) {
			if (expirationTime == -1 || scope.getExpirationTime() < expirationTime) {
				expirationTime = scope.getExpirationTime();
			}
		}
		
		responseBuilder.append("expires_in=").append(expirationTime);
		
		// Calculate scope string
		StringBuilder scopeBuilder = new StringBuilder();
		for (AuthorizationScope scope : result.getRequestedScopes()) {
			scopeBuilder.append(scope.getName()).append(' ');
		}

		scopeBuilder.deleteCharAt(scopeBuilder.length() - 1); // delete last comma

		if (result.getResponseType().equals(OAuthResponseType.TOKEN)) {
			responseBuilder.append("&token_type=Bearer");
		
		DateTime now = new DateTime(DateTimeZone.UTC);

		String accessToken = JWT.create().withIssuer(configurationService.getPublicFqdn())
				.withExpiresAt(now.plusSeconds(expirationTime).toDate()).withIssuedAt(now.toDate())
				.withSubject(userSession.getUserId()).withAudience(result.getSourceApplicationName())
				.withJWTId(UUID.randomUUID().toString()).withClaim("scope", scopeBuilder.toString())
				.sign(Algorithm.RSA256(signingKey));

		responseBuilder.append("&access_token=").append(accessToken);
		}

		if (result.getRelayState() != null) {
			responseBuilder.append("&state=").append(result.getRelayState());
		}

		System.out.println(responseBuilder.toString());
		
		return responseBuilder.toString();
	}

	private boolean checkValidResponseTypes(String responseType) {

		// Only valid response types are "token" and "code"
		if (!responseType.equals(OAuthResponseType.CODE) && !responseType.equals(OAuthResponseType.TOKEN)) {
			LOG.error("ResponseType not supported: {}", responseType);
			return false;
		}

		return true;
	}

	private void checkRedirectUri(OAuthClient client, String redirectUri) throws InvalidRedirectUriException {

		if (!client.getResponseUri().contains(redirectUri)) {
			String message = "Unknown redirectUri: " + redirectUri;
			LOG.error(message);
			throw new InvalidRedirectUriException(message);
		}
	}

	private boolean checkClientAuthorization(OAuthClient client, String responseType, List<String> requestedScopes) {

		if (!responseType.equals(OAuthResponseType.TOKEN) && client.getAllowedGrants().contains(OAuthGrants.IMPLICIT)
				|| !responseType.equals(OAuthResponseType.CODE)
						&& client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {

			LOG.error("Client not authorized to use the response type: {}", responseType);
			return false;
		}

		if (!client.getAllowedScopes().containsAll(requestedScopes)) {

			LOG.error("Client not authorized to use the requested scope");
			return false;
		}

		return true;

	}

}
