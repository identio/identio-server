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
package net.identio.server.service.usersession;

import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import net.identio.server.model.UserSession;
import net.identio.server.service.configuration.ConfigurationService;

@Service
@Scope("singleton")
public class UserSessionService {

	private static final Logger LOG = LoggerFactory.getLogger(UserSessionService.class);

	private LoadingCache<String, UserSession> sessionCache;

	@Autowired
	public UserSessionService(ConfigurationService configurationService) {

		LOG.debug("Initializing in-memory session service");

		sessionCache = CacheBuilder.newBuilder().maximumSize(100000)
				.expireAfterAccess(configurationService.getConfiguration().getSessionConfiguration().getDuration(),
						TimeUnit.MINUTES)
				.build(new CacheLoader<String, UserSession>() {
					public UserSession load(String o) {
						return new UserSession();
					}
				});

		LOG.debug("* Successfully created session cache");
	}

	public UserSession createUserSession() {
		LOG.debug("Creating new session");

		String sessionId = UUID.randomUUID().toString();

		UserSession session = new UserSession();
		session.setId(sessionId);
		sessionCache.put(sessionId, session);

		LOG.debug("New session generated {}", sessionId);

		return session;
	}

	public UserSession getUserSession(String sessionId) {

		UserSession userSession = null;

		if (sessionId != null) {

			LOG.debug("Fetch session {} in cache", sessionId);

			try {
				userSession = sessionCache.get(sessionId);
			} catch (ExecutionException ex) {
				LOG.error("An error occured when loading session from cache: {}", ex.getMessage());
				LOG.debug("* Detailed Stacktrace: ", ex);
			}
		}

		// Check that the session still exists. If not, we create a new one
		if (userSession == null || userSession.getId() == null) {

			LOG.debug("No existing session found");

			userSession = createUserSession();
		}

		return userSession;
	}

	public void removeUserSession(String userSessionId) {

		LOG.debug("Remove session {} from cache", userSessionId);

		sessionCache.invalidate(userSessionId);

	}
}
