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

import net.identio.server.model.Result;
import org.junit.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static org.junit.Assert.*;

public class HttpUtilsTest {

    @Test
    public void getUniqueParam() throws Exception {

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        params.put("key", Collections.singletonList("value"));

        Result<String> result = HttpUtils.getUniqueParam(params, "key");

        assertEquals(Result.ResultStatus.OK, result.getResultStatus());
        assertEquals("value", result.get());


        params = new LinkedMultiValueMap<>();

        params.put("key", Arrays.asList("value1", "value2", "value3"));

        result = HttpUtils.getUniqueParam(params, "key");

        assertEquals(Result.ResultStatus.FAIL, result.getResultStatus());
    }
}