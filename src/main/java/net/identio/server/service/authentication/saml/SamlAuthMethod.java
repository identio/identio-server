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
package net.identio.server.service.authentication.saml;

import net.identio.server.model.AuthMethod;

public class SamlAuthMethod extends AuthMethod {

    private String metadata;
    private boolean certificateCheckEnabled;
    private SamlAuthMap samlAuthMap;

    public String getMetadata() {
        return metadata;
    }

    public SamlAuthMethod setMetadata(String metadata) {
        this.metadata = metadata;
        return this;
    }

    public boolean isCertificateCheckEnabled() {
        return certificateCheckEnabled;
    }

    public SamlAuthMethod setCertificateCheckEnabled(boolean certificateCheckEnabled) {
        this.certificateCheckEnabled = certificateCheckEnabled;
        return this;
    }

    public SamlAuthMap getSamlAuthMap() {
        return samlAuthMap;
    }

    public SamlAuthMethod setSamlAuthMap(SamlAuthMap samlAuthMap) {
        this.samlAuthMap = samlAuthMap;
        return this;
    }
}
