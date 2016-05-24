package com.jinxiaolu.demo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.jinxiaolu.demo.jni.JniUtil;
import com.jinxiaolu.demo.utils.Aes256Cryptor;
import com.jinxiaolu.demo.utils.ApkSignatureProvider;
import com.jinxiaolu.demo.utils.Hmacs256Signer;
import com.kuaikuaiyu.demo.R;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "CIGK_DEMO";
    private static final String TEST_STRING = "{\"status\":\"open\",\"description\":\"版权所有无码必究\",\"pre_order_available\":true,\"bulletin_message\":\"来啊啦\",\"triger_price\":0,\"open_time\":{\"begin\":\"00:00\",\"end\":\"24:00\"},\"logo_url\":\"http:\\/\\/cdn.statics.kuaikuaiyu.com\\/image\\/552bca9b778d176c022d4436.jpg?imageView2\\/2\\/w\\/256\\/h\\/256\",\"name\":\"录哥的测试店铺\",\"isopen\":true,\"image_id\":\"552bca9b778d176c022d4436\",\"send_fees\":0,\"_id\":\"56f214131fa24b00017a81fb\"}";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        testHmacs256();
        testAes256();
        testGetApkSignature();
    }

    /**
     * hmacs256 jni&java test
     */
    private void testHmacs256() {
        Log.d(TAG, "======jni-hmacs256-test======");
        Log.d(TAG, com.jinxiaolu.demo.jni.JniUtil.hmas256Sign(TEST_STRING));
        Log.d(TAG, "======java-hmacs256-test======");
        Log.d(TAG, Hmacs256Signer.hmacs256Sign(TEST_STRING));
    }

    /**
     * aes256 jni&java test
     */
    private void testAes256() {
        try {
            Log.d(TAG, "======jni-encrypt-test======");
            byte[] data = JniUtil.encrypt(TEST_STRING.getBytes("UTF-8"));
            String hexStr = Aes256Cryptor.bytes2HexStr(data);
            Log.d(TAG, hexStr);

            Log.d(TAG, "======java-encrypt-test======");
            byte[] javaData = Aes256Cryptor.encrypt(TEST_STRING.getBytes("UTF-8"));
            String hexJavaStr = Aes256Cryptor.bytes2HexStr(javaData);
            Log.d(TAG, hexJavaStr);

            Log.d(TAG, "======jni-decrypt-test======");
            Log.d(TAG, new String(JniUtil.decrypt(Aes256Cryptor.hexStr2Bytes(hexStr)), "UTF-8"));

            Log.d(TAG, "======java-decrypt-test======");
            Log.d(TAG, new String(Aes256Cryptor.decrypt(Aes256Cryptor.hexStr2Bytes(hexJavaStr)), "UTF-8"));

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    /**
     * apk signature jni&java test
     */
    private void testGetApkSignature() {
        Log.d(TAG, "======jni-get-apk-signature-test======");
        Log.d(TAG, JniUtil.signatureHashCode(this) + "");
        Log.d(TAG, "======java-get-apk-signature-test======");
        Log.d(TAG, ApkSignatureProvider.getApkSianature(this) + "");
    }


}
