package com.omes.srp.demo;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.omes.srp.demo.attest.DemoAttest;
import com.omes.srp.demo.util.Helper;
import com.omes.srp.demo.util.LogUtil;
import com.oplus.omes.srp.sysintegrity.ISrpCallback;
import com.oplus.omes.srp.sysintegrity.SafetyCheck;
import com.oplus.omes.srp.sysintegrity.SrpClient;
import com.oplus.omes.srp.sysintegrity.SrpException;
import com.oplus.omes.srp.sysintegrity.core.AttestInfo;

public class MainActivity extends AppCompatActivity {
    private TextView mTxtMsg = null;
    private AttestInfo mAttestInfo = null;
    private static final int REQUEST_WRITE = 101;
    private EditText mTextAppId;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
        SafetyCheck.init(this);
    }

    private void showInfo(byte[] nonce, AttestInfo info){
        runOnUiThread(()->{
            mTxtMsg.setText("nonce not changed?" + Helper.compare(nonce, mAttestInfo.getNonce()) +
                    "\r\nresult:" + mAttestInfo.getJsonResult());
        });
    }

    private void showErr(SrpException e){
        runOnUiThread(()->{
            mTxtMsg.setText(e.getMessage() + ":" + e.getCode());
        });
    }

    private String getAppId(){
        String appid = mTextAppId.getText().toString();
        LogUtil.d("appId:" + appid);
        return appid;
    }

    public void getTokenAsync(View view){
        final byte[] nonce = Helper.getNonce();
        final String appId = getAppId();
        final long startTime = System.currentTimeMillis();
        LogUtil.d("getTokenStart");
        try {
            //SafetyCheck.getClient(MainActivity.this).needUpgrade();
            SafetyCheck.getClient(MainActivity.this).devAttest(nonce, appId, new ISrpCallback<AttestInfo>() {
                @Override
                public void onFailure(SrpException e) {
                    LogUtil.d("getTokenStop fail");
                    runOnUiThread(()->{
                        mTxtMsg.setText(e.getMessage() + ":" + e.getCode());
                    });
                }

                @Override
                public void onFinish(AttestInfo resp) {
                    LogUtil.d("getTokenStop cost:" + (System.currentTimeMillis() - startTime));
                    mAttestInfo = resp;
                    DemoAttest.action(MainActivity.this, mAttestInfo.getJsonResult());
                    showInfo(nonce, mAttestInfo);
                }
            });
        }catch (SrpException e){
            showErr(e);
            e.printStackTrace();
        }
    }

    private void initTextMsgView(){
        mTxtMsg = findViewById(R.id.txt_msg);
        mTxtMsg.setMovementMethod(ScrollingMovementMethod.getInstance());
    }

    private void initView(){
        initTextMsgView();
        mTextAppId = findViewById(R.id.tv_appid);
        Button btn;
        btn = findViewById(R.id.btn_get_token_async);
        btn.setOnClickListener((v) -> getTokenAsync(v));

        //判断是否有这个权限
        if(ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.READ_EXTERNAL_STORAGE)!= PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(MainActivity.this,new String[]{Manifest.permission.READ_EXTERNAL_STORAGE,Manifest.permission.WRITE_EXTERNAL_STORAGE,Manifest.permission.WAKE_LOCK},REQUEST_WRITE);
            //第一请求权限被取消显示的判断，一般可以不写
            if (ActivityCompat.shouldShowRequestPermissionRationale(MainActivity.this,Manifest.permission.READ_EXTERNAL_STORAGE )) {
                Toast.makeText(MainActivity.this, "please grant permission", Toast.LENGTH_SHORT).show();
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if(requestCode==REQUEST_WRITE&&grantResults[0]== PackageManager.PERMISSION_GRANTED){
            //startFaceVerify();
            Toast.makeText(MainActivity.this,"Permission Allowed",Toast.LENGTH_SHORT).show();
        }

    }
}