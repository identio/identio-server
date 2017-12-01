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
package net.identio.server.service.authentication.x509;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationProvider;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.*;
import net.identio.server.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelCompilerMode;
import org.springframework.expression.spel.SpelParserConfiguration;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
@Scope("singleton")
public class X509AuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(X509AuthenticationProvider.class);

    private HashMap<AuthMethod, Expression> conditionExpressions = new HashMap<>();
    private HashMap<AuthMethod, Expression> uidExpressions = new HashMap<>();

    private HashMap<AuthMethod, X509Certificate> clientTrusts = new HashMap<>();
    private HashMap<AuthMethod, X509Certificate> proxyTrusts = new HashMap<>();

    private List<X509Certificate> serverTrusts = new ArrayList<>();

    private X509AuthenticationProviderConfiguration config;

    @Autowired
    public X509AuthenticationProvider(X509AuthenticationProviderConfiguration config,
                                      AuthenticationService authenticationService) throws InitializationException {

        this.config = config;

        List<X509AuthMethod> authMethods = config.getAuthMethods();

        if (authMethods == null || authMethods.size() == 0)
            return;

        LOG.debug("Initializing X509 Authentication Service");

        //
        for (X509AuthMethod authMethod : authMethods) {

            LOG.debug("* Method: {}", authMethod.getName());

            cacheSpelExpressions(authMethod);
            cacheCertificates(authMethod);
        }

        register(authMethods, authenticationService);

        LOG.info("* X509 Authentication Service initialized");

    }

    public List<X509AuthMethod> getConfiguredAuthMethods() {
        return config.getAuthMethods();
    }

    private void cacheSpelExpressions(X509AuthMethod authMethod) {

        SpelParserConfiguration config = new SpelParserConfiguration(SpelCompilerMode.IMMEDIATE,
                Thread.currentThread().getContextClassLoader());

        ExpressionParser parser = new SpelExpressionParser(config);

        conditionExpressions.put(authMethod, parser.parseExpression(authMethod.getConditionExpression()));
        uidExpressions.put(authMethod, parser.parseExpression(authMethod.getUidExpression()));
    }

    private void cacheCertificates(X509AuthMethod authMethod) throws InitializationException {

        try {

            if (authMethod.getClientCertTrust() != null) {

                X509Certificate cert = SecurityUtils.parseCertificateFile(authMethod.getClientCertTrust());
                clientTrusts.put(authMethod, cert);

                if (authMethod.getSecurity().equals("native")) {
                    serverTrusts.add(cert);
                }
            }

            if (authMethod.getProxyCertTrust() != null) {

                X509Certificate cert = SecurityUtils.parseCertificateFile(authMethod.getProxyCertTrust());
                proxyTrusts.put(authMethod, cert);

                serverTrusts.add(cert);
            }

        } catch (CertificateException | IOException e) {
            throw new InitializationException("Error when parsing certificates for authMethod " + authMethod, e);
        }
    }

    public AuthenticationResult validate(AuthMethod authMethod, Authentication authentication) {

        X509AuthMethod x509AuthMethod = (X509AuthMethod) authMethod;
        X509Authentication x509Authentication = (X509Authentication) authentication;

        Result<X509Certificate> userCertificate = getUserCertificate(x509AuthMethod, x509Authentication);

        if (!userCertificate.isSuccess()) {
            LOG.error("Error when parsing user certificate");

            return AuthenticationResult.fail(AuthenticationErrorStatus.INVALID_CREDENTIALS);
        }

        LOG.debug("Checking X509 certificate user authentication");

        // Check against client trust
        if (!userCertificate.get().getIssuerX500Principal()
                .equals(clientTrusts.get(x509AuthMethod).getSubjectX500Principal())) {
            LOG.error("User certificate rejected: Not emitted by the trusted issuer of method {}",
                    authMethod.getName());

            return AuthenticationResult.fail(AuthenticationErrorStatus.INVALID_CREDENTIALS);
        }

        // Check expressions
        Expression uidExpression = uidExpressions.get(authMethod);
        Expression conditionExpression = conditionExpressions.get(authMethod);

        // Create evaluation context
        StandardEvaluationContext certContext = new StandardEvaluationContext(userCertificate);

        if (conditionExpression.getValue(certContext, Boolean.class)) {
            String uid = uidExpression.getValue(certContext, String.class);

            if (uid != null) {

                LOG.info("User {} successfully authenticated with method {}", uid, authMethod.getName());

                return AuthenticationResult.success().setUserId(uid)
                        .setAuthMethod(authMethod).setAuthLevel(authMethod.getAuthLevel());
            }
        }


        LOG.info("Could not validate user certificate with method {}", authMethod.getName());

        return AuthenticationResult.fail(AuthenticationErrorStatus.INVALID_CREDENTIALS);
    }

    private void register(List<X509AuthMethod> authMethods, AuthenticationService authenticationService) {

        for (X509AuthMethod authMethod : authMethods) {

            LOG.debug("* Registering authentication method {}", authMethod.getName());

            authenticationService.registerTransparent(authMethod, this);
        }
    }

    @Override
    public boolean accepts(Authentication authentication) {
        return authentication instanceof X509Authentication;
    }

    public List<X509Certificate> getServerTrusts() {
        return serverTrusts;
    }

    private Result<X509Certificate> getUserCertificate(X509AuthMethod authMethod, X509Authentication authentication) {

        switch (authMethod.getSecurity()) {

            // Native SSL authentication: the client auth certificate is the user
            // certificate
            case "native":

                return Result.success(authentication.getClientAuthCert()[0]);

            // Shared secret between the SSL endpoint and the server. The
            // certificate is provided via a header
            // Check that a user cert is provided and that the shared secret is
            // valid
            case "shared-secret":

                if (!authMethod.getSharedSecret().equals(authentication.getSharedSecret())) {
                    LOG.error("Provided shared secret is invalid");
                    return Result.fail();
                }

                if (authentication.getUserCert() != null) {
                    return SecurityUtils.parseCertificate(authentication.getUserCert(), authMethod.isApacheFix());
                }

                return Result.fail();

            // Certificate is protected by a 2-way SSL authentication between
            // endpoint and the server
            // Check that client ssl certificate dn and issuer dn are valid
            case "ssl":

                X509Certificate clientAuthCert = authentication.getClientAuthCert()[0];

                if (authentication.getUserCert() != null
                        && authMethod.getProxyCertDn().equals(clientAuthCert.getSubjectX500Principal().getName())
                        && proxyTrusts.get(authMethod).getSubjectX500Principal()
                        .equals(clientAuthCert.getIssuerX500Principal())) {

                    return SecurityUtils.parseCertificate(authentication.getUserCert(), authMethod.isApacheFix());
                }
                return Result.fail();

            default:
                LOG.error("Unknown X509 authentication security " + authMethod.getSecurity());
                return Result.fail();
        }
    }

}
