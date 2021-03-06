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

import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.Result;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.infrastructure.OAuthActorsRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeFetchException;
import net.identio.server.service.oauth.model.*;
import net.identio.server.utils.MiscUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Optional;

@Service
public class AuthorizationCodeService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationCodeService.class);

    @Autowired
    private OAuthActorsRepository actorsRepository;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthorizationService authorizationService;

    public Result<AccessTokenResponse> validateTokenRequest(AuthorizationCodeRequest request, String authorization) {

        // Check that all parameters are correct
        if (!isAuthorizationCodeRequestValid(request))
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        // Fetch and verify client identity
        Client client;
        Result<Client> oAuthClientResult = actorsRepository.getClientFromAuthorization(authorization);

        if (oAuthClientResult.isSuccess()) {
            client = oAuthClientResult.get();
        } else {
            return Result.unauthorized(OAuthErrors.INVALID_CLIENT);
        }

        // Check that the client is authorized to use the authorization code grant
        if (!isAuthorizationCodeGrantAuthorizedForClient(client))
            return Result.fail(OAuthErrors.UNAUTHORIZED_CLIENT);

        // Fetch the authorization code data
        AuthorizationCode code;
        try {
            Optional<AuthorizationCode> result = authorizationCodeRepository.getAuthorizationCodeByValue(request.getCode());

            if (!result.isPresent()) {
                LOG.error("Unknown authorization code");
                return Result.fail(OAuthErrors.INVALID_GRANT);
            }

            code = result.get();

        } catch (AuthorizationCodeFetchException e) {
            return Result.serverError();
        }

        // Verify that the authorization code exist and is not expired
        // Verify that the authorization code was generated for this client
        // Verify that the redirect url matches the one provided in the initial request
        if (!codeExistsAndIsValid(code) ||
                !isCodeGeneratedForClient(code, client) ||
                !redirectUriMatchesInitialRequest(code, request.getRedirectUri()))
            return Result.fail(OAuthErrors.INVALID_GRANT);

        // If a code challenge was submitted, check that the verifier is valid
        if (!isCodeVerifierValid(request.getCodeVerifier(), code.getCodeChallenge(), code.getCodeChallengeMethod()))
            return Result.fail(OAuthErrors.INVALID_GRANT);

        // Everything's ok, generate response
        LinkedHashMap<String, AuthorizationScope> scopes;
        try {
            scopes = authorizationService.deserializeScope(code.getScope());
        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return Result.fail(OAuthErrors.INVALID_GRANT);
        }

        Result<AccessTokenResponse> accessTokenResponse = oAuthResponseService.generateTokenResponse(scopes.values(),
                code.getClientId(), code.getUserId(),
                isRefreshTokenAuthorized(client));

        if (!accessTokenResponse.isSuccess())
            return Result.serverError();

        // Delete authorization code from repository
        try {
            authorizationCodeRepository.delete(code);
        } catch (AuthorizationCodeDeleteException e) {
            return Result.serverError();
        }

        return Result.success(accessTokenResponse.get());
    }

    private boolean isCodeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {

        // If no challenge was present in the initial request, ignore the check
        if (codeChallenge == null)
            return true;

        if (codeVerifier == null) {
            LOG.error("Missing code verifier");
            return false;
        }

        // Assume that the default code challenge is S256
        if (codeChallengeMethod != null && !"S256".equals(codeChallengeMethod)) {
            LOG.error("Unsupported code challenge method {}", codeChallengeMethod);
            return false;
        }

        try {

            String calculatedCodeChallenge = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII)));

            if (codeChallenge.equals(calculatedCodeChallenge)) {
                return true;
            } else {
                LOG.error("Invalid code verifier");
                return false;
            }

        } catch (NoSuchAlgorithmException e) {
            LOG.error("Unable to compute SHA256 hash of the code_verifier {}", codeVerifier);
        }

        return false;
    }

    private boolean isRefreshTokenAuthorized(Client client) {
        return client.getAllowedGrants().contains(OAuthGrants.REFRESH_TOKEN);
    }

    private boolean redirectUriMatchesInitialRequest(AuthorizationCode code, String redirectUri) {

        if (!MiscUtils.equalsWithNulls(code.getRedirectUrl(), redirectUri)) {
            LOG.error("Redirect uri {} doesn't match the initial redirect uri {}", redirectUri, code.getRedirectUrl());
            return false;
        }

        return true;
    }

    private boolean isCodeGeneratedForClient(AuthorizationCode authorizationCode, Client client) {

        if (!authorizationCode.getClientId().equals(client.getClientId())) {
            LOG.error("Authorization code wasn't generated for clientId {} but for {}", client.getClientId(), authorizationCode.getClientId());
            return false;
        }

        return true;
    }

    private boolean codeExistsAndIsValid(AuthorizationCode code) {

        if (code.getExpirationTime() < System.currentTimeMillis() / 1000) {
            LOG.error("Code is expired");
            return false;
        }

        return true;
    }

    private boolean isAuthorizationCodeGrantAuthorizedForClient(Client client) {

        if (!client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {
            LOG.error("Client not authorized to use the authorization code grant");
            return false;
        }

        return true;
    }

    private boolean isAuthorizationCodeRequestValid(AuthorizationCodeRequest request) {

        if (request.getCode() == null) {
            LOG.error("Missing code parameter");
            return false;
        }
        return true;
    }
}
