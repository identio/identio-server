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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.*;

public class DecodeUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DecodeUtils.class);

    public static Result<byte[]> decode(String data, boolean inflate) {

        // First, we decode the B64 string
        byte[] decodedBytes;

        try {
            decodedBytes = Base64.getDecoder().decode(data);

            if (inflate) {
                // try DEFLATE (rfc 1951) -- according to SAML spec
                decodedBytes = inflate(decodedBytes);
            }
        } catch (IllegalArgumentException | IOException ex) {
            return Result.fail();
        }

        return Result.success(decodedBytes);
    }

    public static Result<String> encode(byte[] data, boolean deflate) {

        String encodedString;

        byte[] deflatedData;
        try {
            deflatedData = deflate ? deflate(data) : data;
        } catch (IOException e) {
            return Result.fail();
        }

                encodedString = Base64.getEncoder().encodeToString(deflatedData).replaceAll("\r", "").replaceAll("\n", "");

        return Result.success(encodedString);
    }

    private static byte[] inflate(byte[] data) throws IOException {

        try (ByteArrayOutputStream os = new ByteArrayOutputStream();
             InflaterOutputStream infOs = new InflaterOutputStream(os, new Inflater(true)) ) {

            infOs.write(data);
            infOs.finish();

            return os.toByteArray();
        }
    }

    private static byte[] deflate(byte[] data) throws IOException {

        try (ByteArrayOutputStream os = new ByteArrayOutputStream();
             DeflaterOutputStream defOs = new DeflaterOutputStream(os, new Deflater(7,true))) {

            defOs.write(data);
            defOs.finish();

            return os.toByteArray();
        }
    }
}
