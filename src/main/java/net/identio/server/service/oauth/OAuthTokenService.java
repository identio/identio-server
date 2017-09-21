package net.identio.server.service.oauth;

import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.Result;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.infrastructure.OAuthClientRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeFetchException;
import net.identio.server.service.oauth.model.*;
import net.identio.server.utils.DecodeUtils;
import net.identio.server.utils.MiscUtils;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.zip.DataFormatException;

@Service
public class OAuthTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthTokenService.class);

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private ConfigurationService configurationService;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthorizationService authorizationService;

    public ValidateTokenResult validateTokenRequest(AuthorizationRequest request, String authorization) {

        // Check that all parameters are correct
        if (!isRequestValid(request))
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.FAIL).setErrorStatus(OAuthErrors.INVALID_REQUEST);

        // Check grant type
        if (!isGrantSupported(request.getGrantType()))
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.FAIL).setErrorStatus(OAuthErrors.UNSUPPORTED_GRANT_TYPE);

        // Fetch and verify client identity
        OAuthClient client;
        Result<OAuthClient> oAuthClientResult = extractClientFromAuthorization(authorization);

        if (oAuthClientResult.isSuccess()) {
            client = oAuthClientResult.get();
        } else {
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.UNAUTHORIZED)
                    .setErrorStatus(OAuthErrors.INVALID_CLIENT);
        }

        // Check that the client is authorized to use the authorization code grant
        if (!isGrantAuthorizedForClient(client))
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.FAIL).setErrorStatus(OAuthErrors.UNAUTHORIZED_CLIENT);

        // Fetch the authorization code data
        Optional<AuthorizationCode> code;
        try {
            code = authorizationCodeRepository.getAuthorizationCodeByValue(request.getCode());
        } catch (AuthorizationCodeFetchException e) {
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.SERVER_ERROR);
        }

        // Verify that the authorization code exist and is not expired
        // Verify that the authorization code was generated for this client
        // Verify that the redirect url matches the one provided in the initial request
        if (!codeExistsAndIsValid(code) ||
                !codeGeneratedForClient(code.get(), client) ||
                !redirectUriMatchesInitialRequest(code.get(), request.getRedirectUri()))
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.FAIL).setErrorStatus(OAuthErrors.INVALID_GRANT);

        // Everything's ok, generate response
        LinkedHashMap<String, AuthorizationScope> scopes = null;
        try {
             scopes = authorizationService.deserializeScope(code.get().getScope());
        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.FAIL).setErrorStatus(OAuthErrors.INVALID_GRANT);
        }
        AccessTokenResponse accessTokenResponse = oAuthResponseService.generateTokenResponse(scopes.values(), code.get().getClientId(), code.get().getUserId());

        // Delete authorization code from repository
        try {
            authorizationCodeRepository.delete(code.get());
        } catch (AuthorizationCodeDeleteException e) {
            return new ValidateTokenResult().setStatus(ValidateTokenStatus.SERVER_ERROR);
        }

        return new ValidateTokenResult().setStatus(ValidateTokenStatus.OK).setResponse(accessTokenResponse);
    }

    private boolean redirectUriMatchesInitialRequest(AuthorizationCode code, String redirectUri) {
        return MiscUtils.equalsWithNulls(code.getRedirectUrl(), redirectUri);
    }

    private boolean codeGeneratedForClient(AuthorizationCode authorizationCode, OAuthClient client) {
        return authorizationCode.getClientId().equals(client.getClientId());
    }

    private boolean codeExistsAndIsValid(Optional<AuthorizationCode> code) {
        return code.isPresent() && code.get().getExpirationTime() > System.currentTimeMillis() / 1000;
    }

    private boolean isGrantAuthorizedForClient(OAuthClient client) {
        return client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE);
    }

    private boolean isGrantSupported(String grantType) {
        return OAuthGrants.AUTHORIZATION_CODE.equals(grantType);
    }

    private boolean isRequestValid(AuthorizationRequest request) {
        return request.getGrantType() != null && request.getCode() != null;
    }

    private Result<OAuthClient> extractClientFromAuthorization(String authorization) {

        Result<OAuthClient> result = new Result<>();

        if (authorization != null && authorization.startsWith("Basic ")) {

            try {
                String filteredAuthorization = new String(DecodeUtils.decode(authorization.substring(6), false));

                String[] credentials = filteredAuthorization.split(":");
                String clientId = credentials[0];
                String clientSecret = credentials[1];

                OAuthClient client = clientRepository.getOAuthClientbyId(clientId);

                if (client != null && client.getClientId().equals(clientSecret)) {
                    return result.success(client);
                }

            } catch (IOException | Base64DecodingException | DataFormatException e) {
                LOG.error("Error when decoding Authorization header");
            }
        }

        return result.fail();
    }
}
