package com.jinxiaolu.demo.jni;

import android.content.Context;

/**
 * Author:  Gavin
 * Email:   gavinking@163.com
 * Date:    2016/5/23
 * Desc:
 */
public class JniUtil {
    static {
        System.loadLibrary("jnilib");
    }

    /**
     * hmac256 签名
     *
     * @param msg
     * @return
     */
    public static native String hmas256Sign(String msg);


    /**
     * aes256加密
     *
     * @param data 要加密的数据
     * @return
     */
    public static native byte[] encrypt(byte[] data);

    /**
     * aes解密
     *
     * @param data 要解密的数据
     * @return
     */
    public static native byte[] decrypt(byte[] data);

    /**
     * 获取应用签名的hash code
     * @return
     */
    public static native int signatureHashCode(Object context);
}
