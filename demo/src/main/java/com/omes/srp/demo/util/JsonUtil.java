package com.omes.srp.demo.util;

import com.google.gson.Gson;

public class JsonUtil {
    private static Gson gson = new Gson();


    public static String toJson(Object object){
        return gson.toJson(object);
    }

    public static <T> T fromJson(String json, Class<T> cls){
        return gson.fromJson(json,cls);
    }
}
