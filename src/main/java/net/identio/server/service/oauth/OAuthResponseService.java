package net.identio.server.service.oauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.UserSession;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.exceptions.OAuthException;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.model.*;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.ResponseData;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
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
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.UUID;

@Service
public class OAuthResponseService {

    private static final int AT_DEFAULT_EXPIRATION_TIME = 3600;
    private static final int CODE_DEFAULT_EXPIRATION_TIME = 60;

    private ConfigurationService configurationService;

    private RSAPrivateKey signingKey;
    private RSAPublicKey publicKey;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    public OAuthResponseService(ConfigurationService configurationService) throws InitializationException {
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

    public AccessTokenResponse generateTokenResponse(Collection<AuthorizationScope> scopes, String sourceApplication, String userId) {

        AccessToken at = generateJwtAccessToken(scopes, sourceApplication, userId);

        return new AccessTokenResponse()
                .setAccessToken(at.getValue())
                .setExpiresIn(at.getExpiresIn())
                .setScope(at.getScope())
                .setTokenType(at.getType());
    }

    private AccessToken generateJwtAccessToken(Collection<AuthorizationScope> scopes, String sourceApplication, String userId) {

        int expirationTime = getMinExpirationTime(scopes);

        String serializedScopes = authorizationService.serializeScope(scopes);

        DateTime now = new DateTime(DateTimeZone.UTC);

        return new AccessToken().setValue(JWT.create()
                .withIssuer(configurationService.getConfiguration().getGlobalConfiguration().getPublicFqdn())
                .withExpiresAt(now.plusSeconds(expirationTime).toDate())
                .withIssuedAt(now.toDate())
                .withSubject(userId)
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("scope", serializedScopes)
                .withClaim("client_id", sourceApplication)
                .sign(Algorithm.RSA256(publicKey, signingKey)))
                .setExpiresIn(expirationTime)
                .setType("Bearer")
                .setScope(serializedScopes);
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
