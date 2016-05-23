package com.jinxiaolu.demo.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Author:  Gavin
 * Email:   gavinking@163.com
 * Date:    2016/5/23
 * Desc:
 */
public class Aes256Cryptor {

    // iv同C语言中iv
    private static byte ivBytes[] = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    // keyBytes同C语言中key
    private static byte keyBytes[] = new byte[] { 0x60, 0x3d, (byte) 0xeb,
            0x10, 0x15, (byte) 0xca, 0x71, (byte) 0xbe, 0x2b, 0x73,
            (byte) 0xae, (byte) 0xf0, (byte) 0x85, 0x7d, 0x77, (byte) 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, (byte) 0xd7, 0x2d,
            (byte) 0x98, 0x10, (byte) 0xa3, 0x09, 0x14, (byte) 0xdf,
            (byte) 0xf4 };


    /**
     * 加密
     *
     * @param content
     *            需要加密的内容
     *            加密密码
     * @return
     */
    public static byte[] encrypt(byte[] content) {
        return docrypt(content, keyBytes, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param content
     *            待解密内容
     *            解密密钥
     * @return
     */
    public static byte[] decrypt(byte[] content) {
        return docrypt(content, keyBytes, Cipher.DECRYPT_MODE);
    }

    public static byte[] docrypt(byte[] content, byte[] keyBytes, int mode) {
        try {
            // KeyGenerator kgen = KeyGenerator.getInstance("AES");
            // kgen.init(128, new SecureRandom(keyBytes));
            // SecretKey secretKey = kgen.generateKey();
            // byte[] enCodeFormat = secretKey.getEncoded();

            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // keyBytes32个字节，256位，
            // 与C语言中的key一致
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// 创建密码器
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);

            cipher.init(mode, key, iv);// 初始化
            byte[] result = cipher.doFinal(content);
            return result; // 加密
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 将16进制转换为二进制(服务端)
     *
     * @param hexStr
     * @return
     */
    public static byte[] hexStr2Bytes(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    public static String bytes2HexStr(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            if (((int) data[i] & 0xff) < 0x10) { /* & 0xff转换无符号整型 */
                buf.append("0");
            }
            buf.append(Long.toHexString((int) data[i] & 0xff)); /* 转换16进制,下方法同 */
        }
        return buf.toString();
    }
}
