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
package net.identio.server.service.authpolicy;

import net.identio.saml.SamlConstants;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.model.*;
import net.identio.server.service.authentication.model.AuthenticationResult;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.authpolicy.model.AuthPolicyDecisionStatus;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

@Service
@Scope("singleton")
public class AuthPolicyService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthPolicyService.class);

    @Autowired
    private AuthPolicyConfiguration config;

    public AuthPolicyService() {

        LOG.info("Initializing Authentication Policy Service");
    }

    public ArrayList<AuthLevel> determineTargetAuthLevel(RequestParsingInfo parsingInfo) {

        LOG.debug("Determining authentication strategy for request");

        // Determine the authent level to be applied
        // If the request is signed, we can trust the requested authentication
        // level.
        // Otherwise, we apply the auth level specified in the configuration for
        // this application
        // If none is specified, we apply the default authent level
        List<AuthLevel> requestedAuthLevels = new ArrayList<>();
        String requestedComparison;

        ArrayList<AuthLevel> targetAuthLevels = new ArrayList<>();

        if (parsingInfo.getRequestedAuthLevels() != null) {

            requestedAuthLevels = parsingInfo.getRequestedAuthLevels();
            requestedComparison = parsingInfo.getAuthLevelComparison();

            LOG.debug("* Request specify an auth level. Applying requested auth level");
        } else {
            // Request doesn't specify a minimum auth level
            // , we check if we have a specific auth level
            // for this application
            AppAuthLevel appAuthLevel = config.getAuthLevelByApp(parsingInfo.getSourceApplication());

            if (appAuthLevel != null) {

                AuthLevel selectedAuthLevel = appAuthLevel.getAuthLevel();
                requestedAuthLevels.add(selectedAuthLevel);
                requestedComparison = appAuthLevel.getComparison();

                LOG.debug("* Request does not specify an auth level. Applying app-specific auth level: {} - {}",
                        requestedComparison, selectedAuthLevel.getName());
            } else {

                AuthLevel selectedAuthLevel = config.getEnrichedDefaultAppLevel().getAuthLevel();

                requestedAuthLevels.add(selectedAuthLevel);
                requestedComparison = config.getEnrichedDefaultAppLevel().getComparison();

                LOG.debug("* Request does not specify an auth level. Applying default auth level: {} - {}",
                        requestedComparison, selectedAuthLevel.getName());
            }
        }

        // Determine the target auth levels
        for (AuthLevel authLevel : config.getAllAuthLevels()) {
            int strength = authLevel.getStrength();

            for (AuthLevel requestedAuthLevel : requestedAuthLevels) {

                int requestedStrength = requestedAuthLevel.getStrength();

                if (SamlConstants.COMPARISON_EXACT.equals(requestedComparison) && strength == requestedStrength
                        || SamlConstants.COMPARISON_MINIMUM.equals(requestedComparison)
                        && strength >= requestedStrength
                        || SamlConstants.COMPARISON_MAXIMUM.equals(requestedComparison)
                        && strength <= requestedStrength
                        || SamlConstants.COMPARISON_BETTER.equals(requestedComparison)
                        && strength > requestedStrength) {
                    targetAuthLevels.add(authLevel);
                }

            }
        }

        // Save the required auth levels
        return targetAuthLevels;
    }

    public AuthPolicyDecision checkPreviousAuthSessions(UserSession userSession,
                                                        ArrayList<AuthLevel> targetAuthLevels) {

        LOG.debug("Check previous authentication sessions");

        // We check if the user is already authentified with this auth level
        for (AuthSession authSession : userSession.getAuthSessions()) {
            for (AuthLevel authLevel : targetAuthLevels) {

                if (authSession.getAuthLevel().equals(authLevel)) {

                    LOG.debug("* Found compliant auth session");

                    return new AuthPolicyDecision().setStatus(AuthPolicyDecisionStatus.OK)
                            .setValidatedAuthSession(authSession);
                }
            }
        }

        LOG.debug("* No compliant auth session found. Asking for an explicit authentication");
        return new AuthPolicyDecision().setStatus(AuthPolicyDecisionStatus.AUTH);
    }

    public boolean checkAllowedAuthMethods(HashSet<AuthMethod> targetAuthMethods, AuthMethod submittedAuthMethod) {

        return submittedAuthMethod != null && targetAuthMethods.contains(submittedAuthMethod);
    }

    public AuthPolicyDecision checkAuthPolicyCompliance(UserSession userSession, AuthenticationResult result,
                                                        ArrayList<AuthLevel> targetAuthLevels) {

        // Check that the authlevel matches
        if (targetAuthLevels.contains(result.getAuthLevel())) {

            AuthSession authSession = updateUserSession(userSession, result, result.getAuthLevel());
            return new AuthPolicyDecision().setStatus(AuthPolicyDecisionStatus.OK)
                    .setValidatedAuthSession(authSession);

        } else {
            return new AuthPolicyDecision().setStatus(AuthPolicyDecisionStatus.AUTH);
        }
    }

    public AuthLevel getAuthLevelByUrn(String urn) throws UnknownAuthLevelException {

        AuthLevel authLevel = config.getAuthLevelByUrn(urn);

        if (authLevel == null) {
            LOG.error("Unknown authentication level requested: {}", urn);
            throw new UnknownAuthLevelException("Unknown authentication level requested: " + urn);
        }

        return authLevel;
    }

    public AuthLevel getAuthLevelByName(String name) throws UnknownAuthLevelException {

        AuthLevel authLevel = config.getAuthLevelByName(name);

        if (authLevel == null) {
            LOG.error("Unknown authentication level requested: {}", name);
            throw new UnknownAuthLevelException("Unknown authentication level requested: " + name);
        }

        return authLevel;
    }

    private AuthSession updateUserSession(UserSession userSession, AuthenticationResult result,
                                          AuthLevel authLevel) {

        return userSession.addAuthSession(result.getUserId(), result.getAuthMethod(), authLevel);
    }


}
