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

import static org.junit.Assert.*;

public class MiscUtilsTest {
    @Test
    public void equalsWithNulls() throws Exception {

        assertTrue(MiscUtils.equalsWithNulls(null, null));
        assertTrue(MiscUtils.equalsWithNulls("test", "test"));
        assertFalse(MiscUtils.equalsWithNulls("test", null));
        assertFalse(MiscUtils.equalsWithNulls(null, "test"));
        assertFalse(MiscUtils.equalsWithNulls("test", "test2"));
    }

    @Test
    public void nullIfEmpty() throws Exception {

        assertEquals(null, MiscUtils.nullIfEmpty(""));
        assertEquals("test", MiscUtils.nullIfEmpty("test"));
        assertEquals(null, MiscUtils.nullIfEmpty(null));
    }
}