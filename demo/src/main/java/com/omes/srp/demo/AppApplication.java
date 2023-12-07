package com.omes.srp.demo;

import android.app.Application;

import com.oplus.omes.srp.sysintegrity.util.LogUtil;

public class AppApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        LogUtil.setDebug(true);
    }
}
