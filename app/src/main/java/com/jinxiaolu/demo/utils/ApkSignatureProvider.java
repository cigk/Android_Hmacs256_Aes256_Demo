package com.jinxiaolu.demo.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

/**
 * Author:  Gavin
 * Email:   gavinking@163.com
 * Date:    2016/5/24
 * Desc:    获取应用签名的工具类
 */
public class ApkSignatureProvider {

    public static int getApkSianature(Context ctx) {
        Signature sign = null;
        try {
            PackageInfo info = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(),
                    PackageManager.GET_SIGNATURES);
            sign = info.signatures[0];
//            Log.i("test", "hashCode : " + sign.hashCode());
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return sign.hashCode();
    }
}
