package com.yunjing.eurekaclient2.common.base;


import org.apache.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName ResultInfo
 * @Description 返回数据
 * @Author scyking
 * @Date 2018/12/28 15:53
 * @Version 1.0
 */
public class ResultInfo extends HashMap<String, Object> {
    private static final long serialVersionUID = 1L;

    public ResultInfo() {
        put("code", HttpStatus.SC_OK);
        put("msg", "success");
    }

    public static ResultInfo error() {
        return error(HttpStatus.SC_INTERNAL_SERVER_ERROR, "未知异常，请联系管理员");
    }

    public static ResultInfo error(String msg) {
        return error(HttpStatus.SC_INTERNAL_SERVER_ERROR, msg);
    }

    public static ResultInfo error(int code, String msg) {
        ResultInfo r = new ResultInfo();
        r.put("code", code);
        r.put("msg", msg);
        return r;
    }

    public static ResultInfo ok(String msg) {
        ResultInfo r = new ResultInfo();
        r.put("msg", msg);
        return r;
    }

    public static ResultInfo ok(Map<String, Object> map) {
        ResultInfo r = new ResultInfo();
        r.putAll(map);
        return r;
    }

    public static ResultInfo ok() {
        return new ResultInfo();
    }

    @Override
    public ResultInfo put(String key, Object value) {
        super.put(key, value);
        return this;
    }
}
