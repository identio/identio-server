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
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
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
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OAuthService {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthService.class);
    private static final int AT_DEFAULT_EXPIRATION_TIME = 3600;
    private static final int CODE_DEFAULT_EXPIRATION_TIME = 60;

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

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
        LinkedHashMap<String, AuthorizationScope> scopes;
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

        result.setStatus(RequestParsingStatus.OK).setSourceApplication(client.getClientId()).setResponseUrl(redirectUri)
                .setRequestedScopes(scopes).setResponseType(request.getResponseType()).setConsentNeeded(client.isConsentNeeded());

        return result;
    }

    public ResponseData generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession) {

        return generateSuccessResponse(requestParsingInfo, userSession, requestParsingInfo.getRequestedScopes());
    }

    public ResponseData generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession,
                                                LinkedHashMap<String, AuthorizationScope> approvedScopes) {

        ResponseData responseData = new ResponseData();

        // Determine expiration time of the authorization and scope string
        int expirationTime = getMinExpirationTime(approvedScopes.values());

        String scopeString = getScopeString(approvedScopes.values());

        DateTime now = new DateTime(DateTimeZone.UTC);

        String accessToken = JWT.create()
                .withIssuer(configurationService.getConfiguration().getGlobalConfiguration().getPublicFqdn())
                .withExpiresAt(now.plusSeconds(expirationTime).toDate())
                .withIssuedAt(now.toDate())
                .withSubject(userSession.getUserId())
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("scope", scopeString)
                .withClaim("client_id", requestParsingInfo.getSourceApplication())
                .sign(Algorithm.RSA256(signingKey));

        if (requestParsingInfo.getResponseType().equals(OAuthResponseType.TOKEN)) {

            StringBuilder responseBuilder = new StringBuilder();

            responseBuilder.append(requestParsingInfo.getResponseUrl()).append("#expires_in=");
            responseBuilder.append(expirationTime);

            responseBuilder.append("&token_type=Bearer&access_token=");
            responseBuilder.append(accessToken);

            if (requestParsingInfo.getRelayState() != null) {
                responseBuilder.append("&state=").append(requestParsingInfo.getRelayState());
            }

            responseData.setUrl(responseBuilder.toString());
        }

        if (requestParsingInfo.getResponseType().equals(OAuthResponseType.CODE)) {

            // Generate code
            String code = UUID.randomUUID().toString();

            // Store code + infos
            authorizationCodeRepository.save(code, requestParsingInfo.getSourceApplication(),
                    requestParsingInfo.getResponseUrl(), now.plusSeconds(CODE_DEFAULT_EXPIRATION_TIME));
            // return code url
        }

        return responseData;
    }

    public ResponseData generateErrorResponse(RequestParsingInfo result) {

        return generateErrorResponse(result, true);
    }

    public ResponseData generateErrorResponse(RequestParsingInfo result, boolean consentResult) {

        // Determine the type of error to send
        String errorStatus = consentResult ? result.getErrorStatus() : OAuthErrors.ACCESS_DENIED;

        StringBuilder responseBuilder = new StringBuilder();

        responseBuilder.append(result.getResponseUrl()).append("#error=").append(errorStatus);

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

        if (responseType.equals(OAuthResponseType.TOKEN) && !client.getAllowedGrants().contains(OAuthGrants.IMPLICIT)
                || responseType.equals(OAuthResponseType.CODE)
                && !client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {

            LOG.error("Client not authorized to use the response type: {}", responseType);
            return false;
        }

        if (!client.getAllowedScopes().containsAll(requestedScopes)) {

            LOG.error("Client not authorized to use the requested scope");
            return false;
        }

        return true;
    }

    private int getMinExpirationTime(Collection<AuthorizationScope> scopes) {

        // Determine expiration time of the authorization and scope string
        int expirationTime = -1;

        for (AuthorizationScope scope : scopes) {

            int scopeExpirationTime = scope.getExpirationTime() != 0 ? scope.getExpirationTime() : AT_DEFAULT_EXPIRATION_TIME;

            if (expirationTime == -1 || scopeExpirationTime < expirationTime) {
                expirationTime = scopeExpirationTime;
            }

        }

        return expirationTime;
    }

    private String getScopeString(Collection<AuthorizationScope> scopes) {

        return scopes.stream()
                .map(AuthorizationScope::getName)
                .collect(Collectors.joining(" "));
    }

}
