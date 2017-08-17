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

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;

public class LdapSslSocketFactory extends SSLSocketFactory {

    private static SSLContext context;

    public static synchronized void init(KeyStore keyStore)
            throws KeyManagementException, NoSuchAlgorithmException,
            KeyStoreException {

        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance("X509");
        trustManagerFactory.init(keyStore);
        context = SSLContext.getInstance("TLS");
        context.init(null, trustManagerFactory.getTrustManagers(),
                SecureRandom.getInstance("SHA1PRNG"));
    }

    public static SocketFactory getDefault() {
        return new LdapSslSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return context.getSocketFactory().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return context.getSocketFactory().getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String s, int i, boolean b)
            throws IOException {
        return context.getSocketFactory().createSocket(socket, s, i, b);
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException {
        return context.getSocketFactory().createSocket(s, i);
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i2)
            throws IOException {
        return context.getSocketFactory().createSocket(s, i, inetAddress, i2);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i)
            throws IOException {
        return context.getSocketFactory().createSocket(inetAddress, i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i,
                               InetAddress inetAddress2, int i2) throws IOException {
        return context.getSocketFactory().createSocket(inetAddress, i,
                inetAddress2, i2);
    }
}
