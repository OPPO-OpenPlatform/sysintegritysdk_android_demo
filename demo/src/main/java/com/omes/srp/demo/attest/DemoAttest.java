package com.omes.srp.demo.attest;

import android.content.Context;
import android.util.Base64;
import com.omes.srp.demo.util.LogUtil;
import com.oplus.omes.srp.sysintegrity.core.AttestResponse;
import com.omes.srp.demo.util.JsonUtil;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.TreeSet;

public class DemoAttest {
    private static final String ROOT_CRT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIB3jCCAYOgAwIBAgIOAbdFL8C1Bdm3iAjqbBswCgYIKoZIzj0EAwIwPzELMAkG\n" +
            "A1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMSAwHgYDVQQDDBdPUGx1cyBHbG9iYWwg\n" +
            "Um9vdCBDQSBFMTAeFw0yMTA2MTYwMzEyMTdaFw00NjA2MTYwMzEyMTdaMD8xCzAJ\n" +
            "BgNVBAYTAkNOMQ4wDAYDVQQKDAVPUGx1czEgMB4GA1UEAwwXT1BsdXMgR2xvYmFs\n" +
            "IFJvb3QgQ0EgRTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTIV4ip1eRz9EW\n" +
            "CCSo9Mqq5R2pIMrlImXEQjhdru8NscmfYu07XrXYe4BRI5BiirUyXyYcwBrZCCj2\n" +
            "6kd2bIOmo2MwYTAfBgNVHSMEGDAWgBRU+HQc6qqcMvauDJCHtIQVtdNX4TAPBgNV\n" +
            "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUVPh0HOqqnDL2\n" +
            "rgyQh7SEFbXTV+EwCgYIKoZIzj0EAwIDSQAwRgIhAOtjLMghABOi6eZQbo7WP9kA\n" +
            "ENrzyhUrR6y2jYz0enlbAiEApGOOHbSRXyULplrXu6Fc35UUaXQRFmAtldAhHL7Q\n" +
            "/a0=\n" +
            "-----END CERTIFICATE-----";
    private static final String SRV_CRT = "-----BEGIN CERTIFICATE-----\n" +
            "MIICvjCCAmOgAwIBAgIOATdmwdl1tSliAs8Z8qwwCgYIKoZIzj0EAwIwPzELMAkG\n" +
            "A1UEBhMCQ04xDjAMBgNVBAoMBU9QbHVzMSAwHgYDVQQDDBdPUGx1cyBHbG9iYWwg\n" +
            "Um9vdCBDQSBFMTAeFw0yMTA2MTYwMzUzMjBaFw00MTA2MTYwMzUzMjBaMFMxCzAJ\n" +
            "BgNVBAYTAkNOMQ4wDAYDVQQKDAVPUGx1czEWMBQGA1UECwwNT1BsdXMgU2Vydmlj\n" +
            "ZTEcMBoGA1UEAwwTT1BsdXMgU2VydmljZSBDQSBFMTBZMBMGByqGSM49AgEGCCqG\n" +
            "SM49AwEHA0IABBOLpHwYzzaZEDJqxjA8ZZvuR2cZ9MsSeSCpiJiLGHS/KxX0SREU\n" +
            "jTqEvf7WO65lFuBZiHx4ELtlQ8KDp5Ap//ujggEtMIIBKTB9BggrBgEFBQcBAQRx\n" +
            "MG8wRQYIKwYBBQUHMAKGOWh0dHA6Ly9vcGx1c3RydXN0LmNvbS9pc3N1ZXIvZ2xv\n" +
            "YmFscm9vdGNhLWUxX2RpZ2ljZXJ0LmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29w\n" +
            "bHVzdHJ1c3QuY29tL29jc3AwHwYDVR0jBBgwFoAUVPh0HOqqnDL2rgyQh7SEFbXT\n" +
            "V+EwDwYDVR0TAQH/BAUwAwEB/zBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vb3Bs\n" +
            "dXN0cnVzdC5jb20vY3JsL2dsb2JhbHJvb3RjYS1lMV9kaWdpY2VydC5jcmwwDgYD\n" +
            "VR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSbVQjSzLnbVMO7XZNNQMCRi0QhoTAKBggq\n" +
            "hkjOPQQDAgNJADBGAiEA7qQibbJ40ICfkPO7W7GGIMfAXIxWUS3AVIMaJoqEdGUC\n" +
            "IQDbSli+zlY29e/2zGrv8EEa7CN9I+woFpLdxzIKlc/Tlg==\n" +
            "-----END CERTIFICATE-----";

    public static boolean action(Context context, String jsonAttestResp){
        try {
            AttestResponse response = JsonUtil.fromJson(jsonAttestResp, AttestResponse.class);
            if (response.getoCerts() != null || response.getoCerts().length >0) {
                X509Certificate[] certs = pem2X509s(response.getoCerts());
                boolean chainPass = verifyCertificateChain(certs);
                if (chainPass) {
                    byte[] content = getSortedContent(context, response);
                    LogUtil.d("verify data len: " + content.length);
                    byte[] sha = sha256(content);
                    LogUtil.d("sign sha256 data: " + String.format("%x", new BigInteger(1, sha)));
                    boolean verifyRet = verify(response.getSignature(), content, certs[certs.length - 1]);
                    LogUtil.d("verifyRet:" + verifyRet);
                    return true;
                } else {
                    LogUtil.e("verifyChain failed");
                    return false;
                }
            }else {
                LogUtil.e("oCerts is null");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    private static void write2File(Context context, String content){
        try {
            String path = context.getExternalFilesDir(null).getPath();
            File f = new File(path , "content.txt");
            BufferedWriter bf = new BufferedWriter(new FileWriter(f));
            bf.write(content);
            bf.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static X509Certificate pem2X509Certificate(String pem) throws CertificateException {
        ByteArrayInputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    private static X509Certificate[] pem2X509s(String[] ocerts) throws CertificateException {
        X509Certificate[] certs = new X509Certificate[3];
        certs[0] = pem2X509Certificate(ROOT_CRT);
        certs[1] = pem2X509Certificate(SRV_CRT);
        certs[2] = pem2X509Certificate(ocerts[0]);
        return certs;
    }
    private static byte[] getSortedContent(Context context, AttestResponse resp){
        StringBuilder sb = new StringBuilder();
        TreeSet<String> content = new TreeSet<>();
        content.add("bizToken" + resp.getToken());
        content.add("effectiveTime" + resp.getValidTime());
        content.add("timestamp" + resp.getAddTime());
        content.add("sysIntegrity" + resp.isSysIntegrity());
        content.add("nonce" + resp.getNonce());

        if (resp.getoCerts() != null) {
            content.add("oCerts" + String.join(";", resp.getoCerts()));
        } else {
            content.add("oCerts");
        }
        content.add("pkgName" + resp.getPkgName());
        content.add("certMD5" + resp.getCertMd());
        if (resp.getDetail() != null) {
            content.add("detail" + String.join(";", resp.getDetail()));
        } else {
            content.add("detail");
        }
        if (resp.getAdvice() != null) {
            content.add("advice" + String.join(";", resp.getAdvice()));
        }else {
            content.add("advice");
        }
        for (String item : content){
            sb.append(item).append(";");
        }
        String joinValue = sb.toString();
        LogUtil.d("verify data::" + joinValue);
        write2File(context, joinValue);
        return joinValue.getBytes();
    }

    public static byte[] sha256(byte[] input) {
        MessageDigest digest = getDigest("SHA-256");
        digest.update(input);
        return digest.digest();
    }

    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static boolean verifyCertificateChain(X509Certificate[] certs){
        try{
            X509Certificate root = certs[0];
            X509Certificate parent = root;
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                cert.checkValidity();
                cert.verify(parent.getPublicKey());
                parent = cert;
            }
            return true;
        } catch (Exception e){
            e.printStackTrace();
            LogUtil.e("attest verifyCertChain failed");
            return false;
        }
    }

    public static boolean verify(String sig, byte[] content, X509Certificate cert){
        try{
            byte[] sigByte = Base64.decode(sig, Base64.DEFAULT);
            LogUtil.d("sig, %x:" + String.format("%x", new BigInteger(1, sigByte)));
            PublicKey pubKey = cert.getPublicKey();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(pubKey);
            signature.update(content);
            boolean ret = signature.verify(sigByte);
            return ret;
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
}
