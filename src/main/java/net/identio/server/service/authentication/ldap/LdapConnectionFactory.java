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
package net.identio.server.service.authentication.ldap;

import net.identio.server.model.LdapAuthMethod;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import java.util.Hashtable;

public class LdapConnectionFactory extends BasePooledObjectFactory<InitialLdapContext> {

    private static final Logger LOG = LoggerFactory.getLogger(LdapConnectionFactory.class);

    private LdapAuthMethod ldapAuthMethod;

    private int currentUrlIndex;

    public LdapConnectionFactory(LdapAuthMethod ldapAuthMethod) {
        this.ldapAuthMethod = ldapAuthMethod;

        currentUrlIndex = 0;
    }

    @Override
    public InitialLdapContext create() throws NamingException {

        InitialLdapContext ctx = createContext(ldapAuthMethod, ldapAuthMethod.getProxyUser(),
                ldapAuthMethod.getProxyPassword());

        LOG.debug("Created LDAP connection to: {}", ldapAuthMethod.getName());

        return ctx;
    }

    public boolean authenticate(String name, String dn, String password) {

        InitialLdapContext ctx = null;

        try {
            ctx = createContext(ldapAuthMethod, dn, password);

            return true;
        } catch (NamingException e) {

            return false;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    LOG.error("Error when closing connection to LDAP {}", ldapAuthMethod.getName());
                }
            }
        }
    }

    private InitialLdapContext createContext(LdapAuthMethod ldapAuthMethod, String userDn, String password)
            throws NamingException {

        LOG.debug("Begin creation of an LDAP connection to: {}", ldapAuthMethod.getName());

        int currentUrlIndexTs = currentUrlIndex;

        String currentUrl = ldapAuthMethod.getLdapUrl()[currentUrlIndexTs];

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, currentUrl);

        if (currentUrl.startsWith("ldaps://")) {

            // Add a custom SSL Socket factory to validate server CA
            env.put("java.naming.ldap.factory.socket",
                    "net.identio.server.service.authentication.ldap.LdapSslSocketFactory");
        }

        if (userDn != null) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, userDn);
            env.put(Context.SECURITY_CREDENTIALS, password);
        }

        InitialLdapContext ctx;

        try {
            ctx = new InitialLdapContext(env, null);
        } catch (CommunicationException e) {

            LOG.error("Error when contacting LDAP server {}", ldapAuthMethod.getLdapUrl()[currentUrlIndexTs]);

            if (ldapAuthMethod.getLdapUrl().length > 1) {
                int newCurrentUrlIndex = currentUrlIndexTs < ldapAuthMethod.getLdapUrl().length - 1
                        ? currentUrlIndexTs + 1 : 0;

                LOG.error("Switching to LDAP server {}", ldapAuthMethod.getLdapUrl()[newCurrentUrlIndex]);

                currentUrlIndex = newCurrentUrlIndex;

                env.put(Context.PROVIDER_URL, ldapAuthMethod.getLdapUrl()[newCurrentUrlIndex]);

                ctx = new InitialLdapContext(env, null);
            } else {
                throw e;
            }
        }

        return ctx;
    }

    @Override
    public PooledObject<InitialLdapContext> wrap(InitialLdapContext ctx) {
        return new DefaultPooledObject<>(ctx);
    }

    @Override
    public void destroyObject(PooledObject<InitialLdapContext> p) {

        LOG.debug("Begin destruction of an LDAP connection to: {}", ldapAuthMethod.getName());

        try {
            p.getObject().close();

            LOG.debug("Destroyed LDAP connection to: {}", ldapAuthMethod.getName());

        } catch (NamingException e) {
            LOG.error("Error when closing connection to LDAP server {}", ldapAuthMethod.getName());
        }
    }

    @Override
    public boolean validateObject(PooledObject<InitialLdapContext> p) {

        LOG.debug("Validating connection to LDAP directory {}", ldapAuthMethod.getName());

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setCountLimit(1);
        controls.setTimeLimit(500);

        try {
            p.getObject().search("", ldapAuthMethod.getPoolConfig().getTestRequestFilter(), controls);
        } catch (NamingException e) {
            LOG.error("Validation of connection to LDAP directory {} failed", ldapAuthMethod.getName());
            return false;
        }

        return true;
    }

}
