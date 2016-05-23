package com.jinxiaolu.demo.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Author:  Gavin
 * Email:   gavinking@163.com
 * Date:    2016/5/23
 * Desc:    hmacs256签名工具类
 */
public class Hmacs256Signer {
    //Key保持和jni中的key一致
    private static final String SIGN_KEY =
            "0f654197bba48eac7a36d32dae278a7ab4e1d29c80ad80d5617c5a555c0b8385";


    /**
     * hmacs256 签名
     *
     * @param msg
     * @return
     */
    public static String hmacs256Sign(String msg) {
        SecretKeySpec keySpec = new SecretKeySpec(SIGN_KEY.getBytes(), "HmacSHA256");
        StringBuilder signature = new StringBuilder();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            byte[] result = mac.doFinal(msg.getBytes("UTF-8"));
            for (byte b : result) {
                signature.append(byteToHexString(b));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signature.toString();
    }


    private static String byteToHexString(byte ib) {
        char[] Digit = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
                'e', 'f'};
        char[] ob = new char[2];
        ob[0] = Digit[(ib >>> 4) & 0X0f];
        ob[1] = Digit[ib & 0X0F];
        return new String(ob);
    }
}
