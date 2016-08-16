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
package net.identio.server.service.authentication.ldap;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.apache.commons.pool2.impl.GenericObjectPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.AuthMethod;
import net.identio.server.model.Authentication;
import net.identio.server.model.AuthenticationResult;
import net.identio.server.model.AuthenticationResultStatus;
import net.identio.server.model.ErrorStatus;
import net.identio.server.model.LdapAuthMethod;
import net.identio.server.model.LdapPoolConfig;
import net.identio.server.model.TransactionData;
import net.identio.server.model.UserPasswordAuthentication;
import net.identio.server.service.authentication.AuthenticationProvider;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.utils.SecurityUtils;

@Service
@Scope("singleton")
public class LdapAuthenticationProvider implements AuthenticationProvider {

	private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticationProvider.class);

	private HashMap<String, GenericObjectPool<InitialLdapContext>> pools = new HashMap<String, GenericObjectPool<InitialLdapContext>>();

	private HashMap<String, LdapAuthMethod> ldapAuthMethodsMap = new HashMap<String, LdapAuthMethod>();

	@Autowired
	public LdapAuthenticationProvider(ConfigurationService configurationService,
			AuthenticationService authenticationService) throws InitializationException {

		List<LdapAuthMethod> authMethods = configurationService.getConfiguration().getAuthMethodConfiguration()
				.getLdapAuthMethods();

		if (authMethods == null)
			return;

		LOG.debug("Initializing LDAP Authentication Service");

		initTrustore(authMethods);

		initPool(authMethods);

		register(authMethods, authenticationService);

		LOG.info("* LDAP Authentication Service initialized");

	}

	public AuthenticationResult validate(AuthMethod authMethod, Authentication authentication,
			TransactionData transactionData) {

		LdapAuthMethod ldapAuthMethod = (LdapAuthMethod) authMethod;
		UserPasswordAuthentication userPwAuthentication = (UserPasswordAuthentication) authentication;

		boolean validation = false;

		String userId = userPwAuthentication.getUserId();
		String password = userPwAuthentication.getPassword();

		GenericObjectPool<InitialLdapContext> pool = pools.get(authMethod.getName());

		InitialLdapContext ctx = null;

		try {
			ctx = pool.borrowObject();

			// First we search the user
			SearchControls controls = new SearchControls();
			controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

			String searchFilter = ldapAuthMethod.getUserSearchFilter().replace("#UID",
					SecurityUtils.escapeLDAPSearchFilter(userId));

			NamingEnumeration<SearchResult> results = ctx.search(ldapAuthMethod.getBaseDn(), searchFilter, controls);

			SearchResult result = null;

			if (results.hasMoreElements()) {
				result = results.next();

				if (results.hasMoreElements()) {
					LOG.error("User ID {} is not unique in LDAP {}", userId, authMethod.getName());
					return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
							.setErrorStatus(ErrorStatus.AUTH_USER_NOT_UNIQUE);
				}
			} else {
				LOG.error("User ID {} does not exist in LDAP {}", userId, authMethod.getName());
				return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
						.setErrorStatus(ErrorStatus.AUTH_INVALID_CREDENTIALS);
			}

			// Try to bind with the found user id
			validation = ((LdapConnectionFactory) pool.getFactory()).authenticate(authMethod.getName(),
					result.getNameInNamespace(), password);

			pool.returnObject(ctx);

			if (validation) {
				LOG.info("User {} successfully authenticated with {}", userId, authMethod.getName());
				return new AuthenticationResult().setStatus(AuthenticationResultStatus.SUCCESS).setUserId(userId)
						.setAuthMethod(authMethod).setAuthLevel(authMethod.getAuthLevel());
			} else {
				LOG.error("Authentication failed for user {} with {}", userId, authMethod.getName());
				return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
						.setErrorStatus(ErrorStatus.AUTH_INVALID_CREDENTIALS);
			}

		} catch (Exception ex) {

			// Discard context
			try {
				if (ctx != null) {
					pool.invalidateObject(ctx);
				}
			} catch (Exception ex2) {
				LOG.error("An error occurend when authenticating user");
			}

			return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
					.setErrorStatus(ErrorStatus.AUTH_TECHNICAL_ERROR);
		}

	}

	private void initPool(List<LdapAuthMethod> ldapAuthMethods) {

		for (LdapAuthMethod ldapAuthMethod : ldapAuthMethods) {

			LOG.debug("* Auth Method: {}", ldapAuthMethod.getName());

			ldapAuthMethodsMap.put(ldapAuthMethod.getName(), ldapAuthMethod);

			LdapConnectionFactory factory = new LdapConnectionFactory(ldapAuthMethod);

			GenericObjectPool<InitialLdapContext> pool = new GenericObjectPool<InitialLdapContext>(factory);

			LdapPoolConfig poolConfig = ldapAuthMethod.getPoolConfig();

			pool.setMinIdle(poolConfig.getMinIdleConnections());
			pool.setMaxIdle(poolConfig.getMaxIdleConnections());
			pool.setBlockWhenExhausted(true);
			pool.setTestWhileIdle(poolConfig.isTestWhileIdle());
			pool.setTestOnBorrow(poolConfig.isTestOnBorrow());
			pool.setTimeBetweenEvictionRunsMillis(1000 * poolConfig.getTimeBetweenEvictionRuns());
			pool.setNumTestsPerEvictionRun(poolConfig.getNumTestsPerEvictionRun());
			pool.setMinEvictableIdleTimeMillis(1000 * poolConfig.getMinEvictableIdleTime());

			pools.put(ldapAuthMethod.getName(), pool);

		}
	}

	private void initTrustore(List<LdapAuthMethod> ldapAuthMethods) throws InitializationException {

		LOG.debug("* Init trust store for SSL connections");

		// Init keystore
		try {

			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, null);

			// Add each trust certificate to the keystore
			for (LdapAuthMethod ldapAuthMethod : ldapAuthMethods) {

				if (ldapAuthMethod.getTrustCert() != null) {

					SecurityUtils.addCertificateToKeyStore(ks,
							SecurityUtils.parseCertificate(ldapAuthMethod.getTrustCert()), ldapAuthMethod.getName());
				}
			}

			LdapSslSocketFactory.init(ks);

		} catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException ex) {
			throw new InitializationException("Error when initializing keystore with trusted certificates", ex);
		}
	}

	private void register(List<LdapAuthMethod> authMethods, AuthenticationService authenticationService) {

		for (LdapAuthMethod authMethod : authMethods) {

			LOG.debug("* Registering authentication method {}", authMethod.getName());

			authenticationService.registerExplicit(authMethod, this);
		}
	}

	@Override
	public boolean accepts(Authentication authentication) {
		return authentication instanceof UserPasswordAuthentication;
	}
}
