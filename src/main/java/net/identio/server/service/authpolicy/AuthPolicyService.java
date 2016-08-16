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
package net.identio.server.service.authpolicy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import net.identio.saml.SamlConstants;
import net.identio.server.exceptions.AuthMethodNotAllowedException;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.exceptions.UnknownAuthMethodException;
import net.identio.server.model.AppAuthLevel;
import net.identio.server.model.AuthLevel;
import net.identio.server.model.AuthMethod;
import net.identio.server.model.AuthMethodConfiguration;
import net.identio.server.model.AuthPolicyConfiguration;
import net.identio.server.model.AuthPolicyDecision;
import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.AuthSession;
import net.identio.server.model.AuthenticationResult;
import net.identio.server.model.SamlAuthMethod;
import net.identio.server.model.State;
import net.identio.server.model.StepUpAuthMethod;
import net.identio.server.model.UserSession;
import net.identio.server.service.configuration.ConfigurationService;

@Service
@Scope("singleton")
public class AuthPolicyService {

	private static final Logger LOG = LoggerFactory.getLogger(AuthPolicyService.class);

	private AuthPolicyConfiguration authPolicyConfiguration;
	private AuthMethodConfiguration authMethodConfiguration;

	private HashMap<String, AuthLevel> authLevelByUrn = new HashMap<>();;
	private HashMap<String, AppAuthLevel> authLevelByApp = new HashMap<>();
	private HashMap<String, AuthMethod> authMethodByName = new HashMap<>();

	@Autowired
	public AuthPolicyService(ConfigurationService configurationService) {

		LOG.debug("Initialization of auth policy service");

		authPolicyConfiguration = configurationService.getConfiguration().getAuthPolicyConfiguration();
		authMethodConfiguration = configurationService.getConfiguration().getAuthMethodConfiguration();

		// Index auth levels
		int index = 0;
		for (AuthLevel authLevel : authPolicyConfiguration.getAuthLevels()) {
			authLevel.setStrength(index);
			authLevelByUrn.put(authLevel.getUrn(), authLevel);
			index++;
		}

		// Index app-specific auth levels
		List<AppAuthLevel> appAuthLevels = authPolicyConfiguration.getApplicationSpecificAuthLevel();

		if (appAuthLevels != null) {
			for (AppAuthLevel appAuthLevel : appAuthLevels) {
				authLevelByApp.put(appAuthLevel.getAppName(), appAuthLevel);
			}
		}

		// Index auth methods
		for (AuthMethod authMethod : authMethodConfiguration.getAuthMethods()) {
			authMethodByName.put(authMethod.getName(), authMethod);
		}

	}

	public ArrayList<AuthLevel> determineTargetAuthLevel(AuthRequestValidationResult arValidationResult) {

		LOG.debug("Determining authentication strategy for request");

		// Determine the authent level to be applied
		// If the request is signed, we can trust the requested authentication
		// level.
		// Otherwise, we apply the auth level specified in the configuration for
		// this application
		// If none is specified, we apply the default authent level
		ArrayList<AuthLevel> requestedAuthLevels = new ArrayList<>();
		String requestedComparison = null;

		ArrayList<AuthLevel> targetAuthLevels = new ArrayList<>();

		if (arValidationResult.getRequestedAuthLevels() != null) {

			requestedAuthLevels = arValidationResult.getRequestedAuthLevels();
			requestedComparison = arValidationResult.getAuthLevelComparison();

			LOG.debug("* Request specify an auth level. Applying requested auth level");
		} else {
			// Request doesn't specify a minimum auth level
			// , we check if we have a specific auth level
			// for this application
			AppAuthLevel appAuthLevel = authLevelByApp.get(arValidationResult.getSourceApplicationName());

			if (appAuthLevel != null) {

				AuthLevel selectedAuthLevel = appAuthLevel.getAuthLevel();
				requestedAuthLevels.add(selectedAuthLevel);
				requestedComparison = appAuthLevel.getComparison();

				LOG.debug("* Request does not specify an auth level. Applying app-specific auth level: {} - {}",
						requestedComparison, selectedAuthLevel.getName());
			} else {

				AuthLevel selectedAuthLevel = authPolicyConfiguration.getDefaultAuthLevel().getAuthLevel();

				requestedAuthLevels.add(selectedAuthLevel);
				requestedComparison = authPolicyConfiguration.getDefaultAuthLevel().getComparison();

				LOG.debug("* Request does not specify an auth level. Applying default auth level: {} - {}",
						requestedComparison, selectedAuthLevel.getName());
			}
		}

		// Determine the target auth levels
		for (AuthLevel authLevel : authPolicyConfiguration.getAuthLevels()) {
			int strength = authLevel.getStrength();

			for (AuthLevel requestedAuthLevel : requestedAuthLevels) {

				int requestedStrength = requestedAuthLevel.getStrength();

				if ((SamlConstants.COMPARISON_EXACT.equals(requestedComparison) && strength == requestedStrength)
						|| (SamlConstants.COMPARISON_MINIMUM.equals(requestedComparison)
								&& strength >= requestedStrength)
						|| (SamlConstants.COMPARISON_MAXIMUM.equals(requestedComparison)
								&& strength <= requestedStrength)
						|| (SamlConstants.COMPARISON_BETTER.equals(requestedComparison)
								&& strength > requestedStrength)) {
					targetAuthLevels.add(authLevel);
				}

			}
		}

		// Save the required auth levels
		return targetAuthLevels;
	}

	public HashSet<AuthMethod> determineTargetAuthMethods(ArrayList<AuthLevel> targetAuthLevels) {

		HashSet<AuthMethod> nextAuthMethods = new HashSet<>();

		for (AuthMethod authMethod : authMethodConfiguration.getAuthMethods()) {

			if (authMethod instanceof SamlAuthMethod) {

				// Check if the authentication level is supported
				HashMap<AuthLevel, String> outMap = ((SamlAuthMethod) authMethod).getSamlAuthMap().getOut();

				for (AuthLevel targetAuthLevel : targetAuthLevels) {
					if (outMap.containsKey(targetAuthLevel)) {
						nextAuthMethods.add(authMethod);
						break;
					}
				}
				continue;
			}

			if (targetAuthLevels.contains(authMethod.getAuthLevel())) {
				nextAuthMethods.add(authMethod);
			}
		}

		return nextAuthMethods;
	}

	public AuthPolicyDecision checkPreviousAuthSessions(UserSession userSession,
			ArrayList<AuthLevel> targetAuthLevels) {

		LOG.debug("Check previous authentication sessions");

		// We check if the user is already authentified with this auth level
		for (AuthSession authSession : userSession.getAuthSessions()) {
			for (AuthLevel authLevel : targetAuthLevels) {

				if (authSession.getAuthLevel().equals(authLevel)) {

					LOG.debug("* Found compliant auth session");

					return new AuthPolicyDecision(State.RESPONSE, authSession, null);
				}
			}
		}

		LOG.debug("* No compliant auth session found. Asking for an explicit authentication");
		return new AuthPolicyDecision(State.AUTH, null, null);
	}

	public void checkAllowedAuthMethods(State state, HashSet<AuthMethod> targetAuthMethods,
			AuthMethod selectedAuthMethod, AuthMethod submittedAuthMethod)
					throws UnknownAuthMethodException, AuthMethodNotAllowedException {

		if (submittedAuthMethod == null) {
			throw new UnknownAuthMethodException("Unknown authentication method");
		}

		// Check if the used authentication method is a valid step-up
		// authentication method
		switch (state) {
		case AUTH:
			if (!targetAuthMethods.contains(submittedAuthMethod)) {
				throw new AuthMethodNotAllowedException("Authentication method " + submittedAuthMethod.getName()
						+ " is not allowed for this transaction");
			}
			break;

		case STEP_UP_AUTHENTICATION:
			if (!selectedAuthMethod.getStepUpAuthentication().getAuthMethod().equals(submittedAuthMethod)) {
				throw new AuthMethodNotAllowedException("Authentication method " + submittedAuthMethod.getName()
						+ " is not allowed for this transaction");
			}
		default:
		}
	}

	public AuthPolicyDecision checkAuthPolicyCompliance(UserSession userSession, AuthenticationResult result,
			ArrayList<AuthLevel> targetAuthLevels, AuthMethod selectedAuthMethod, State state) {

		if (state == State.STEP_UP_AUTHENTICATION) {

			AuthSession authSession = updateUserSession(userSession, result,
					selectedAuthMethod.getStepUpAuthentication(),
					selectedAuthMethod.getStepUpAuthentication().getAuthLevel());
			return new AuthPolicyDecision(State.RESPONSE, authSession, null);
		}

		if (result.getAuthMethod().getStepUpAuthentication() != null) {

			LOG.debug("* This method has a step-up authentication declared");

			return new AuthPolicyDecision(State.STEP_UP_AUTHENTICATION, null,
					new HashSet<AuthMethod>(Arrays.asList(result.getAuthMethod())));

		} else {
			// Check that the authlevel matches
			if (targetAuthLevels.contains(result.getAuthLevel())) {
				AuthSession authSession = updateUserSession(userSession, result, null, result.getAuthLevel());
				return new AuthPolicyDecision(State.RESPONSE, authSession, null);
			} else {
				return new AuthPolicyDecision(state, null, null);
			}
		}
	}

	public AuthLevel getAuthLevelByUrn(String urn) throws UnknownAuthLevelException {

		AuthLevel authLevel = authLevelByUrn.get(urn);

		if (authLevel == null) {
			LOG.error("Unknown authentication level requested: {}", urn);
			throw new UnknownAuthLevelException("Unknown authentication level requested: " + urn);
		}

		return authLevel;
	}

	public AuthMethod getAuthMethodByName(String name) throws UnknownAuthMethodException {

		AuthMethod authMethod = authMethodByName.get(name);

		if (authMethod == null) {
			throw new UnknownAuthMethodException("Unknown authentication method requested: " + name);
		}

		return authMethod;
	}

	public String getLogo(String authMethodName) {

		try {
			return getAuthMethodByName(authMethodName).getLogoFileName();
		} catch (UnknownAuthMethodException e) {
			return null;
		}
	}

	private AuthSession updateUserSession(UserSession userSession, AuthenticationResult result,
			StepUpAuthMethod stepupAuthMethod, AuthLevel authLevel) {
		return userSession.addAuthSession(result.getUserId(), result.getAuthMethod(), stepupAuthMethod, authLevel);
	}
}
