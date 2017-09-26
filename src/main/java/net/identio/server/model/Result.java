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

package net.identio.server.model;

public class Result<T> {

    private T result;
    private boolean success;
    private String errorStatus;

    public Result<T> success(T result) {
        this.result = result;
        this.success = true;
        return this;
    }

    public Result<T> fail(String errorStatus) {
        this.errorStatus = errorStatus;
        this.success = false;
        return this;
    }

    public Result<T> fail() {
        this.success = false;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public T get() {
        return result;
    }

    public boolean isSuccess() {
        return success;
    }


}
