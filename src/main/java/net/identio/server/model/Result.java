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

    public enum ErrorType {
        FAIL, SERVER_ERROR, UNAUTHORIZED
    }

    private T result;
    private ErrorType errorType;
    private String errorStatus;

    private Result(T result) {
        this.result = result;
    }

    private Result() {
    }

    public static <T> Result<T> success(T result) {
        return new Result<>(result);
    }

    public static <T> Result<T> fail(String errorStatus) {
        Result<T> response = new Result<>();
        response.errorType = ErrorType.FAIL;
        response.errorStatus = errorStatus;
        return response;
    }

    public static <T> Result<T> fail() {
        Result<T> response = new Result<>();
        response.errorType = ErrorType.FAIL;
        return response;
    }

    public static <T> Result<T> serverError() {
        Result<T> response = new Result<>();
        response.errorType = ErrorType.SERVER_ERROR;
        return response;
    }

    public static <T> Result<T> unauthorized() {
        Result<T> response = new Result<>();
        response.errorType = ErrorType.UNAUTHORIZED;
        return response;
    }

    public ErrorType getErrorType() {
        return this.errorType;
    }

    public String getErrorStatus() {
        return this.errorStatus;
    }

    public T get() {
        return result;
    }

    public boolean isSuccess() {
        return result != null;
    }
}
