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
