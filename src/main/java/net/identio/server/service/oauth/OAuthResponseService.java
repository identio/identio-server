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
import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.Result;
import net.identio.server.model.UserSession;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.oauth.infrastructure.RefreshTokenRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.exceptions.OAuthException;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.RefreshTokenCreationException;
import net.identio.server.service.oauth.model.*;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.ResponseData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

@Service
public class OAuthResponseService {

    private static final int AT_DEFAULT_EXPIRATION_TIME = 3600;
    private static final int CODE_DEFAULT_EXPIRATION_TIME = 60;

    private RSAPrivateKey signingKey;
    private RSAPublicKey publicKey;

    private GlobalConfiguration globalConfiguration;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    public OAuthResponseService(GlobalConfiguration globalConfiguration) throws InitializationException {

        this.globalConfiguration = globalConfiguration;

        // Cache signing certificate
        try (FileInputStream fis = new FileInputStream(globalConfiguration.getSignatureKeystorePath())) {

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, globalConfiguration.getSignatureKeystorePassword().toCharArray());

            Enumeration<String> aliases = ks.aliases();

            if (aliases == null || !aliases.hasMoreElements()) {
                throw new InitializationException("Keystore doesn't contain a certificate");
            }

            String alias = aliases.nextElement();

            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                    new KeyStore.PasswordProtection(globalConfiguration.getSignatureKeystorePassword().toCharArray()));

            signingKey = (RSAPrivateKey) keyEntry.getPrivateKey();
            publicKey = (RSAPublicKey) keyEntry.getCertificate().getPublicKey();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableEntryException ex) {
            throw new InitializationException("Could not initialize OAuth Service", ex);
        }
    }


    public ResponseData generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession) throws OAuthException {

        return generateSuccessResponse(requestParsingInfo, userSession, requestParsingInfo.getRequestedScopes());
    }

    public ResponseData generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession,
                                                LinkedHashMap<String, AuthorizationScope> approvedScopes) throws OAuthException {

        ResponseData responseData = new ResponseData();

        StringBuilder responseBuilder = new StringBuilder();
        responseBuilder.append(requestParsingInfo.getResponseUrl());

        if (requestParsingInfo.getResponseType().equals(OAuthResponseType.TOKEN)) {

            AccessToken at = generateJwtAccessToken(approvedScopes.values(), requestParsingInfo.getSourceApplication(),
                    userSession.getUserId());

            responseBuilder
                    .append("#expires_in=")
                    .append(at.getExpiresIn())
                    .append("&token_type=")
                    .append(at.getType())
                    .append("&access_token=")
                    .append(at.getValue());

            if (requestParsingInfo.getRelayState() != null) {
                responseBuilder.append("&state=").append(requestParsingInfo.getRelayState());
            }

            responseData.setUrl(responseBuilder.toString());
        }

        if (requestParsingInfo.getResponseType().equals(OAuthResponseType.CODE)) {

            // Generate code
            String codeValue = UUID.randomUUID().toString();

            responseBuilder.append("?code=").append(codeValue);

            responseBuilder.append("&state=").append(requestParsingInfo.getRelayState());

            // Generate authorization code
            AuthorizationCode code = new AuthorizationCode()
                    .setCode(codeValue)
                    .setClientId(requestParsingInfo.getSourceApplication())
                    .setRedirectUrl(requestParsingInfo.getResponseUrl())
                    .setExpirationTime(System.currentTimeMillis() / 1000 + CODE_DEFAULT_EXPIRATION_TIME)
                    .setScope(authorizationService.serializeScope(approvedScopes.values()))
                    .setUserId(userSession.getUserId());

            // Store code
            try {
                authorizationCodeRepository.save(code);
            } catch (AuthorizationCodeCreationException e) {
                throw new OAuthException(e.getMessage(), e);
            }
            responseData.setUrl(responseBuilder.toString());
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

    public Result<AccessTokenResponse> generateTokenResponse(Collection<AuthorizationScope> scopes, String sourceApplication,
                                                             String userId, boolean addRefreshToken) {

        AccessTokenResponse response = new AccessTokenResponse();

        AccessToken at = generateJwtAccessToken(scopes, sourceApplication, userId);

        response.setAccessToken(at.getValue())
                .setExpiresIn(at.getExpiresIn())
                .setScope(at.getScope())
                .setTokenType(at.getType());

        if (addRefreshToken) {

            Result<String> rt = generateRefreshToken(at);

            if (rt.isSuccess()) {
                response.setRefreshToken(rt.get());
            } else {
                return Result.serverError();
            }
        }
        return Result.success(response);
    }

    private Result<String> generateRefreshToken(AccessToken at) {

        RefreshToken rt = new RefreshToken()
                .setValue(UUID.randomUUID().toString())
                .setClientId(at.getClientId())
                .setExpiresIn(at.getExpiresIn())
                .setScope(at.getScope())
                .setUserId(at.getUserId());

        try {
            refreshTokenRepository.save(rt);
        } catch (RefreshTokenCreationException e) {
            return Result.serverError();
        }

        return Result.success(rt.getValue());
    }

    private AccessToken generateJwtAccessToken(Collection<AuthorizationScope> scopes, String sourceApplication, String userId) {

        int expirationTime = getMinExpirationTime(scopes);

        String serializedScopes = authorizationService.serializeScope(scopes);

        Instant now = Instant.now();

        return new AccessToken()
                .setExpiresIn(expirationTime)
                .setType("Bearer")
                .setScope(serializedScopes)
                .setClientId(sourceApplication).setUserId(userId)
                .setValue(JWT.create()
                        .withIssuer(globalConfiguration.getPublicFqdn())
                        .withExpiresAt(Date.from(now.plusSeconds(expirationTime)))
                        .withIssuedAt(Date.from(now))
                        .withSubject(userId)
                        .withJWTId(UUID.randomUUID().toString())
                        .withClaim("scope", serializedScopes)
                        .withClaim("client_id", sourceApplication)
                        .sign(Algorithm.RSA256(publicKey, signingKey)));

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

}
