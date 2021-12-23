package com.cycredit.login_center.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseMessage<T> implements Serializable {
    private Integer code;

    private T data;

    private String message;


    public static <T> ResponseMessage ok(T data) {
        return new ResponseMessage(200, data, "操作成功");
    }

    public static <T> ResponseMessage ok(T data, String msg) {
        return new ResponseMessage(200, data, msg);
    }

    public static ResponseMessage error(String msg) {
        return new ResponseMessage(500, null, msg);
    }

    public static <T> ResponseMessage error(T data, String msg) {
        return new ResponseMessage(500, data, msg);
    }

    public static <T> ResponseMessage error(Integer code, T data, String msg) {
        return new ResponseMessage(code, data, msg);
    }
}
