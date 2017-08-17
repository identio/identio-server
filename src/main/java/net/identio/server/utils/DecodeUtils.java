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

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class DecodeUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DecodeUtils.class);

    /**
     * Utility method to Base64-decode and eventually inflate a string
     *
     * @param value      Value to decode
     * @param isDeflated Indicates if the string should be inflated
     * @return
     * @throws Base64DecodingException
     * @throws DataFormatException
     * @throws Exception
     */
    public static byte[] decode(String data, boolean inflate)
            throws IOException, Base64DecodingException, DataFormatException {

        LOG.debug("Decoding string {} with inflate = {}", data, inflate);

        // First, we decode the B64 string
        byte[] decodedBytes = Base64.decode(data);

        if (inflate) {
            try {
                // try DEFLATE (rfc 1951) -- according to SAML spec
                decodedBytes = inflate(decodedBytes, true);

            } catch (IOException ze) {
                // try zlib (rfc 1950)
                decodedBytes = inflate(decodedBytes, false);
            }
        }

        LOG.debug("Finished decoding string");

        return decodedBytes;
    }

    /**
     * Utility method to Base64-encode and eventually deflate data
     *
     * @param value   Value to encode
     * @param deflate Indicates if the string should be deflated
     * @return Encoded string
     * @throws IOException
     */
    public static String encode(byte[] data, boolean deflate) throws IOException {

        LOG.debug("Encoding data in base 64 with deflate = {}", deflate);

        String encodedString = null;

        byte[] deflatedData = deflate ? deflate(data, true) : data;

        // First, we decode the B64 string
        encodedString = Base64.encode(deflatedData).replaceAll("\r", "").replaceAll("\n", "");

        LOG.debug("Encoded string: {}", encodedString);

        return encodedString;
    }

    /**
     * Utility method to inflate a compressed string
     *
     * @param bytes  Bytes to decode
     * @param nowrap Should wrapping be used
     * @return Decoded bytes
     * @throws IOException
     * @throws DataFormatException
     * @throws Exception
     */
    private static byte[] inflate(byte[] data, boolean nowrap) throws IOException, DataFormatException {

        LOG.debug("Inflating string with nowrap = {}...", nowrap);

        Inflater decompressor = new Inflater(nowrap);
        decompressor.setInput(data);

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buf = new byte[512];

            while (!decompressor.finished()) {
                int count = decompressor.inflate(buf);
                out.write(buf, 0, count);
            }

            LOG.debug("String inflated successfully");

            return out.toByteArray();

        } finally {
            if (decompressor != null)
                decompressor.end();
        }
    }

    /**
     * Utility method to deflate an uncompressed string
     *
     * @param bytes  Bytes to decode
     * @param nowrap Should wrapping be used
     * @return Decoded bytes
     * @throws IOException
     * @throws Exception
     */
    private static byte[] deflate(byte[] data, boolean nowrap) throws IOException {

        LOG.debug("Deflating string with nowrap = {}...", nowrap);

        Deflater deflater = new Deflater(7, nowrap);
        deflater.setInput(data);
        deflater.finish();

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {

            byte[] buffer = new byte[1024];

            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                outputStream.write(buffer, 0, count);
            }

            outputStream.close();

            return outputStream.toByteArray();
        } finally {
            if (deflater != null)
                deflater.end();
        }
    }
}
