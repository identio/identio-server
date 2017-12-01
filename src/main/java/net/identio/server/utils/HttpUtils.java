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
import org.springframework.util.MultiValueMap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

public class HttpUtils {

    public static void setSessionCookie(HttpServletResponse httpResponse, String sessionId,
                                        boolean secure) {

        Cookie sessionCookie = new Cookie("identioSession", sessionId);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setMaxAge(-1); // Session cookie
        sessionCookie.setPath("/");
        sessionCookie.setSecure(secure);
        httpResponse.addCookie(sessionCookie);
    }

    public static Result<String> getUniqueParam(MultiValueMap<String, String> allParams, String param) {

        List<String> paramList = allParams.getOrDefault(param, new ArrayList<>());

        if (paramList.size() > 1) return Result.fail();

        return paramList.size() == 1 ?
                Result.success(MiscUtils.nullIfEmpty(paramList.get(0)))
                : Result.success(null);
    }
}
