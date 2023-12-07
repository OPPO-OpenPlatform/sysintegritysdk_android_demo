package com.omes.srp.demo.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Helper {
    public static byte[] getNonce(){
        byte[] nonce = new byte[16];
        try {
            SecureRandom random;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                random = SecureRandom.getInstanceStrong();
            } else {
                random = SecureRandom.getInstance("SHA1PRNG");
            }
            random.nextBytes(nonce);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return nonce;
    }

    public static boolean compare(byte[] nonce1, byte[] nonce2){
        if (nonce1 == null || nonce2 == null)   return false;
        if (nonce1.length != nonce2.length) return false;
        for (int i=0; i<nonce1.length; ++i){
            if (nonce1[i] != nonce2[i]){
                return false;
            }
        }
        return true;
    }
}
