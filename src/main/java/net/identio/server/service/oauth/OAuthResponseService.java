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
import net.identio.server.service.oauth.infrastructure.TokenRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.TokenCreationException;
import net.identio.server.service.oauth.model.*;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.ResponseData;
import net.identio.server.utils.SecurityUtils;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

@Service
public class OAuthResponseService {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthResponseService.class);

    private static final int AT_DEFAULT_EXPIRATION_TIME = 3600;
    private static final int CODE_DEFAULT_EXPIRATION_TIME = 60;
    private static final int TOKEN_LENGTH = 100;

    private RSAPrivateKey signingKey;
    private RSAPublicKey publicKey;

    private GlobalConfiguration globalConfiguration;

    @Autowired
    private OAuthConfiguration oAuthConfiguration;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private TokenRepository tokenRepository;

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


    public Result<ResponseData> generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession) {

        return generateSuccessResponse(requestParsingInfo, userSession, requestParsingInfo.getRequestedScopes());
    }

    public Result<ResponseData> generateSuccessResponse(RequestParsingInfo requestParsingInfo, UserSession userSession,
                                                        LinkedHashMap<String, AuthorizationScope> approvedScopes) {

        ResponseData responseData = new ResponseData();

        StringBuilder responseBuilder = new StringBuilder();
        responseBuilder.append(requestParsingInfo.getResponseUrl());

        if (requestParsingInfo.getResponseType().equals(OAuthResponseType.TOKEN)) {

            Result<OAuthToken> atResult = generateAccessToken(approvedScopes.values(), requestParsingInfo.getSourceApplication(),
                    userSession.getUserId());

            if (!atResult.isSuccess()) {
                LOG.error("Error when generating JWT Access Token");
                return Result.serverError();
            }

            OAuthToken at = atResult.get();

            responseBuilder
                    .append("#expires_in=")
                    .append(at.getExpiration() - at.getIssuedAt())
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
            String codeValue = SecurityUtils.generateSecureIdentifier(TOKEN_LENGTH);

            responseBuilder.append("?code=").append(codeValue);

            responseBuilder.append("&state=").append(requestParsingInfo.getRelayState());

            // Generate authorization code
            AuthorizationCode code = new AuthorizationCode()
                    .setCode(codeValue)
                    .setClientId(requestParsingInfo.getSourceApplication())
                    .setRedirectUrl(requestParsingInfo.getResponseUrl())
                    .setExpirationTime(System.currentTimeMillis() / 1000 + CODE_DEFAULT_EXPIRATION_TIME)
                    .setScope(authorizationService.serializeScope(approvedScopes.values()))
                    .setUserId(userSession.getUserId())
                    .setCodeChallenge(requestParsingInfo.getChallenge())
                    .setCodeChallengeMethod(requestParsingInfo.getChallengeMethod());

            // Store code
            try {
                authorizationCodeRepository.save(code);
            } catch (AuthorizationCodeCreationException e) {
                return Result.serverError();
            }
            responseData.setUrl(responseBuilder.toString());
        }

        return Result.success(responseData);
    }

    public Result<ResponseData> generateErrorResponse(RequestParsingInfo result) {

        return generateErrorResponse(result, true);
    }

    public Result<ResponseData> generateErrorResponse(RequestParsingInfo result, boolean consentResult) {

        // Determine the type of error to send
        String errorStatus = consentResult ? result.getErrorStatus() : OAuthErrors.ACCESS_DENIED;

        StringBuilder responseBuilder = new StringBuilder();

        responseBuilder.append(result.getResponseUrl()).append("#error=").append(errorStatus);

        if (result.getRelayState() != null) {
            responseBuilder.append("&state=").append(result.getRelayState());
        }

        return Result.success(new ResponseData().setUrl(responseBuilder.toString()));
    }

    public Result<AccessTokenResponse> generateTokenResponse(Collection<AuthorizationScope> scopes, String sourceApplication,
                                                             String userId, boolean addRefreshToken) {

        AccessTokenResponse response = new AccessTokenResponse();

        Result<OAuthToken> atResult = generateAccessToken(scopes, sourceApplication, userId);

        if (!atResult.isSuccess()) return Result.serverError();

        OAuthToken at = atResult.get();

        response.setAccessToken(at.getValue())
                .setExpiresIn(at.getExpiration() - at.getIssuedAt())
                .setScope(at.getScope())
                .setTokenType(at.getType());

        if (addRefreshToken) {

            Result<String> rtResult = generateRefreshToken(at);

            if (rtResult.isSuccess()) {
                response.setRefreshToken(rtResult.get());
            } else {
                return Result.serverError();
            }
        }

        return Result.success(response);
    }

    private Result<String> generateRefreshToken(OAuthToken at) {

        OAuthToken refresh = new OAuthToken()
                .setType(OAuthToken.REFRESH_TOKEN_TYPE)
                .setValue(SecurityUtils.generateSecureIdentifier(TOKEN_LENGTH))
                .setClientId(at.getClientId())
                .setScope(at.getScope())
                .setUsername(at.getUsername())
                .setIssuedAt(at.getIssuedAt())
                .setNotBefore(at.getNotBefore())
                .setAudience(at.getAudience())
                .setIssuer(at.getIssuer())
                .setSubject(at.getSubject());

        try {
            tokenRepository.save(refresh);
        } catch (TokenCreationException e) {
            return Result.serverError();
        }

        return Result.success(refresh.getValue());
    }

    private Result<OAuthToken> generateAccessToken(Collection<AuthorizationScope> scopes, String sourceApplication, String userId) {

        int expirationTime = getMinExpirationTime(scopes);

        String serializedScopes = authorizationService.serializeScope(scopes);

        Instant now = Instant.now();
        long epoch = now.toEpochMilli() / 1000;

        String jwtId = UUID.randomUUID().toString();

        OAuthToken accessToken = new OAuthToken()
                .setType(OAuthToken.BEARER_TOKEN_TYPE)
                .setIssuer(globalConfiguration.getBasePublicUrl())
                .setScope(serializedScopes)
                .setExpiration(epoch + expirationTime)
                .setClientId(sourceApplication)
                .setUsername(userId)
                .setIssuedAt(epoch)
                .setNotBefore(epoch)
                .setJwtId(jwtId)
                .setSubject(userId);

        if (oAuthConfiguration.isJwtToken()) {
            accessToken.setValue(JWT.create()
                    .withIssuer(globalConfiguration.getBasePublicUrl())
                    .withExpiresAt(Date.from(now.plusSeconds(expirationTime)))
                    .withIssuedAt(Date.from(now))
                    .withSubject(userId)
                    .withNotBefore(Date.from(now))
                    .withJWTId(jwtId)
                    .withClaim("scope", serializedScopes)
                    .withClaim("client_id", sourceApplication)
                    .sign(Algorithm.RSA256(publicKey, signingKey)));
        } else {
            accessToken.setValue(SecurityUtils.generateSecureIdentifier(TOKEN_LENGTH));
        }

        try {
            tokenRepository.save(accessToken);
        } catch (TokenCreationException e) {
            return Result.serverError();
        }

        return Result.success(accessToken);
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
