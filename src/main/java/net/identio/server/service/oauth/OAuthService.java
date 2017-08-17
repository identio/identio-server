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
package net.identio.server.service.oauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.*;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.model.OAuthClient;
import net.identio.server.service.oauth.model.OAuthErrors;
import net.identio.server.service.oauth.model.OAuthGrants;
import net.identio.server.service.oauth.model.OAuthResponseType;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.RequestParsingStatus;
import net.identio.server.service.orchestration.model.ResponseData;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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

    public RequestParsingInfo validateAuthentRequest(OAuthInboundRequest request) {

        RequestParsingInfo result = new RequestParsingInfo();

        result.setProtocolType(ProtocolType.OAUTH);

        // Handle state and copy it in the response
        if (request.getState() != null) {
            result.setRelayState(request.getState());
        }

        // Fetch client
        OAuthClient client = clientRepository.getOAuthClientbyId(request.getClientId());
        if (client == null) {
            return result.setStatus(RequestParsingStatus.FATAL_ERROR).setErrorStatus(OAuthErrors.UNKNOWN_CLIENT);
        }

        // Verify redirectUri
        String redirectUri = client.getResponseUri().get(0);

        if (request.getRedirectUri() != null) {
            if (checkRedirectUri(client, request.getRedirectUri())) {
                redirectUri = request.getRedirectUri();
            } else {
                return result.setStatus(RequestParsingStatus.FATAL_ERROR).setErrorStatus(OAuthErrors.UNKNOWN_REDIRECT_URI);
            }
        }

        // Validate response type value
        if (request.getResponseType() == null || !checkValidResponseTypes(request.getResponseType())) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.RESPONSE_TYPE_NOT_SUPPORTED)
                    .setResponseUrl(redirectUri);
        }

        // Validate scope value
        List<AuthorizationScope> scopes;
        try {
            scopes = authorizationService.getScopes(request.getScopes());
        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.INVALID_SCOPE).setResponseUrl(redirectUri);
        }

        // Validate client authorization regarding allowed scopes and response
        // types
        if (!checkClientAuthorization(client, request.getResponseType(), request.getScopes())) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.UNAUTHORIZED_CLIENT).setResponseUrl(redirectUri);
        }

        result.setStatus(RequestParsingStatus.OK).setSourceApplicationName(client.getName()).setResponseUrl(redirectUri)
                .setRequestedScopes(scopes).setResponseType(request.getResponseType());

        return result;
    }

    public ResponseData generateSuccessResponse(RequestParsingInfo result, UserSession userSession) {

        StringBuilder responseBuilder = new StringBuilder();

        responseBuilder.append(result.getResponseUrl()).append("#expires_in=");

        // Determine expiration time of the authorization
        int expirationTime = -1;
        for (AuthorizationScope scope : result.getRequestedScopes()) {

            int scopeExpirationTime = scope.getExpirationTime() != 0 ? scope.getExpirationTime() : 3600;

            if (expirationTime == -1 || scopeExpirationTime < expirationTime) {
                expirationTime = scopeExpirationTime;
            }
        }

        responseBuilder.append(expirationTime);

        // Calculate scope string
        StringBuilder scopeBuilder = new StringBuilder();
        for (AuthorizationScope scope : result.getRequestedScopes()) {
            scopeBuilder.append(scope.getName()).append(' ');
        }

        scopeBuilder.deleteCharAt(scopeBuilder.length() - 1); // delete last comma

        if (result.getResponseType().equals(OAuthResponseType.TOKEN)) {
            responseBuilder.append("&token_type=Bearer&access_token=");

            DateTime now = new DateTime(DateTimeZone.UTC);

            String accessToken = JWT.create().withIssuer(configurationService.getPublicFqdn())
                    .withExpiresAt(now.plusSeconds(expirationTime).toDate()).withIssuedAt(now.toDate())
                    .withSubject(userSession.getUserId()).withAudience(result.getSourceApplicationName())
                    .withJWTId(UUID.randomUUID().toString()).withClaim("scope", scopeBuilder.toString())
                    .sign(Algorithm.RSA256(signingKey));

            responseBuilder.append(accessToken);
        }

        if (result.getRelayState() != null) {
            responseBuilder.append("&state=").append(result.getRelayState());
        }

        return new ResponseData().setUrl(responseBuilder.toString());
    }

    public ResponseData generateErrorResponse(RequestParsingInfo result) {

        StringBuilder responseBuilder = new StringBuilder();

        responseBuilder.append(result.getResponseUrl()).append("#error=").append(result.getErrorStatus());

        if (result.getRelayState() != null) {
            responseBuilder.append("&state=").append(result.getRelayState());
        }

        return new ResponseData().setUrl(responseBuilder.toString());
    }

    private boolean checkValidResponseTypes(String responseType) {

        // Only valid response types are "token" and "code"
        if (!responseType.equals(OAuthResponseType.CODE) && !responseType.equals(OAuthResponseType.TOKEN)) {
            LOG.error("ResponseType not supported: {}", responseType);
            return false;
        }

        return true;
    }

    private boolean checkRedirectUri(OAuthClient client, String redirectUri) {

        if (!client.getResponseUri().contains(redirectUri)) {
            String message = "Unknown redirectUri: " + redirectUri;
            LOG.error(message);
            return false;
        }

        return true;
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
