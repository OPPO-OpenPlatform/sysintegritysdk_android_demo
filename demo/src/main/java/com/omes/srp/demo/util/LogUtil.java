package com.omes.srp.demo.util;

import android.util.Log;

public class LogUtil {
    private static final String TAG = "srpdemo";

    public static void d(String message){
        Log.d(TAG, System.currentTimeMillis() + "|||" + message);
    }

    public static void e(String message){
        Log.e(TAG,System.currentTimeMillis() + "|||" + message);
    }
}
