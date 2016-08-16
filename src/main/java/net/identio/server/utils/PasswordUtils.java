/*
 This file is part of Ident.io

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.utils;

import java.io.Console;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordUtils {

	public static void main(String[] args) {

		int rounds = 10;

		if (args.length == 1) {
			rounds = Integer.parseInt(args[0]);

			if (rounds < 4 || rounds > 31) {
				System.out.println("Error: valid rounds range is 4-31");
				return;
			}
		}

		Console console = System.console();

		char[] password = console.readPassword("Enter password: ");
		// String password = "password";
		String hashedPassword = BCrypt.hashpw(new String(password), BCrypt.gensalt(rounds));

		System.out.println("Hashed password: " + hashedPassword);
	}

}
