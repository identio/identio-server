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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.Security;
import java.util.UUID;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
public class SecurityUtilsTest {
    @Test
    public void escapeDN() throws Exception {

        String escapedDn = SecurityUtils.escapeDN("cn=toto;toto+toto\\toto,ou=test<>\"toto");

        assertEquals("cn=toto\\;toto\\+toto\\\\toto\\,ou=test\\<\\>\\\"toto", escapedDn);
    }

    @Test
    public void escapeLDAPSearchFilter() throws Exception {

        String escapedFilter = SecurityUtils.escapeLDAPSearchFilter("(&(objectclass=toto\\)(uid=*)(cn=\u0000test");

        assertEquals("\\28&\\28objectclass=toto\\5c\\29\\28uid=\\2a\\29\\28cn=\\00test", escapedFilter);

    }

    @Test
    public void generateSecureIdentifier() throws Exception {

        String identifier = SecurityUtils.generateSecureIdentifier(30);

        assertEquals(30, identifier.length());
    }

    @Test
    public void encrypt() throws Exception {

        Security.setProperty("crypto.policy", "unlimited");

        String plain = UUID.randomUUID().toString();

        String encrypt = SecurityUtils.encrypt(plain);

        assertEquals(plain, SecurityUtils.decrypt(encrypt));
    }
}