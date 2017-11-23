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
package net.identio.server.utils;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

public class SecurityUtils {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final String LOWERCASE = UPPERCASE.toLowerCase();

    private static final String DIGITS = "0123456789";

    private static final char[] ALPHANUM = (UPPERCASE + LOWERCASE + DIGITS).toCharArray();

    private static final SecureRandom random = new SecureRandom();

    private static final TextEncryptor encryptor = Encryptors.text(KeyGenerators.string().generateKey(),
            KeyGenerators.string().generateKey());

    public static String escapeDN(String name) {
        StringBuilder sb = new StringBuilder();

        if (name.length() > 0 && (name.charAt(0) == ' ' || name.charAt(0) == '#')) {
            sb.append('\\'); // add the leading backslash if needed
        }

        for (int i = 0; i < name.length(); i++) {
            char curChar = name.charAt(i);
            switch (curChar) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case ',':
                    sb.append("\\,");
                    break;
                case '+':
                    sb.append("\\+");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '<':
                    sb.append("\\<");
                    break;
                case '>':
                    sb.append("\\>");
                    break;
                case ';':
                    sb.append("\\;");
                    break;
                default:
                    sb.append(curChar);
                    break;
            }
        }

        if (name.length() > 1 && name.charAt(name.length() - 1) == ' ') {
            sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if
            // needed
        }

        return sb.toString();
    }

    public static String escapeLDAPSearchFilter(String filter) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < filter.length(); i++) {
            char curChar = filter.charAt(i);
            switch (curChar) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(curChar);
                    break;
            }
        }
        return sb.toString();
    }


    public static void addCertificateToKeyStore(KeyStore ks, X509Certificate cert, String alias)
            throws KeyStoreException {

        ks.setCertificateEntry(alias, cert);
    }

    public static boolean createKeyStoreWithCertificates(String keystorePath, String keystorePassword,
                                                         List<X509Certificate> certificates) {

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);

            for (X509Certificate cert : certificates) {
                SecurityUtils.addCertificateToKeyStore(ks, cert, UUID.randomUUID().toString());
            }

            ks.store(fos, keystorePassword.toCharArray());

            return true;

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            return false;
        }
    }

    public static X509Certificate parseCertificate(String path)
            throws IOException, CertificateException {

        try (FileInputStream fis = new FileInputStream(path); BufferedInputStream bis = new BufferedInputStream(fis)) {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            return (X509Certificate) cf.generateCertificate(bis);
        }
    }

    public static String generateSecureIdentifier(int length) {

        char[] buf = new char[length];

        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = ALPHANUM[random.nextInt(ALPHANUM.length)];
        return new String(buf);
    }

    public static String encrypt(String plain) {
        return encryptor.encrypt(plain);
    }

    public static String decrypt(String encrypted) {
        return encryptor.decrypt(encrypted);
    }
}
