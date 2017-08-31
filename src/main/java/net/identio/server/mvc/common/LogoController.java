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
package net.identio.server.mvc.common;

import net.identio.server.service.authpolicy.AuthPolicyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@Controller
public class LogoController {

    private static final Logger LOG = LoggerFactory.getLogger(LogoController.class);

    @Autowired
    private AuthPolicyService authPolicyService;

    @RequestMapping(value = "/logo/{authMethodName}", method = RequestMethod.GET)
    public ResponseEntity<InputStreamResource> getLogo(@PathVariable("authMethodName") String authMethodName) {

        String fileName = authPolicyService.getLogo(authMethodName);

        if (fileName == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        File file = new File(fileName);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentLength(file.length());

        if (fileName.endsWith(".png")) {
            headers.setContentType(MediaType.IMAGE_PNG);
        }
        if (fileName.endsWith(".jpg")) {
            headers.setContentType(MediaType.IMAGE_JPEG);
        }

        try {
            InputStreamResource inputStreamResource = new InputStreamResource(new FileInputStream(file));
            return new ResponseEntity<>(inputStreamResource, headers, HttpStatus.OK);

        } catch (IOException e) {
            LOG.error("Error when accessing logo file {}: {}", fileName, e.getMessage());
            LOG.debug("* Detailed stacktrace:", e);
        }

        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
