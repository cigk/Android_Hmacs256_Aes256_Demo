//
// Created by Gavin on 2016/5/8.
//
#include "com_jinxiaolu_demo_jni_JniUtil.h"
#include <android/log.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , "KKY", __VA_ARGS__)
//CRYPT CONFIG
#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 256
#define READ_LEN 10

//AES_IV
static unsigned char AES_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//AES_KEY
static unsigned char AES_KEY[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71,
		0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c,
		0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
		0xf4 };

jbyteArray native_aes(JNIEnv *env,jbyteArray jarray, jint jmode) {
  	//check input data
  	unsigned int len = (unsigned int) ((*env)->GetArrayLength(env, jarray));
  	if (len <= 0 || len >= MAX_LEN) {
  		return NULL;
  	}

  	unsigned char *data = (unsigned char*) (*env)->GetByteArrayElements(env,
  			jarray, NULL);
  	if (!data) {
  		return NULL;
  	}

  	//计算填充长度，当为加密方式且长度不为16的整数倍时，则填充，与3DES填充类似(DESede/CBC/PKCS5Padding)
  	unsigned int mode = (unsigned int) jmode;
  	unsigned int rest_len = len % AES_BLOCK_SIZE;
  	unsigned int padding_len = (
  			(ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
  	unsigned int src_len = len + padding_len;

  	//设置输入
  	unsigned char *input = (unsigned char *) malloc(src_len);
  	memset(input, 0, src_len);
  	memcpy(input, data, len);
  	if (padding_len > 0) {
  		memset(input + len, (unsigned char) padding_len, padding_len);
  	}
  	//data不再使用
  	(*env)->ReleaseByteArrayElements(env, jarray, data, 0);

  	//设置输出Buffer
  	unsigned char * buff = (unsigned char*) malloc(src_len);
  	if (!buff) {
  		free(input);
  		return NULL;
  	}
  	memset(buff, src_len, 0);

  	//set key & iv
  	unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 }; //>=53(这里取64)
  	aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);

  	//执行加解密计算(CBC mode)
  	if (mode == ENCRYPT) {
  		aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
  				AES_IV);
  	} else {
  		aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
  				AES_IV);
  	}

  	//解密时计算填充长度
  	if (ENCRYPT != mode) {
  		unsigned char * ptr = buff;
  		ptr += (src_len - 1);
  		padding_len = (unsigned int) *ptr;
  		if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
  			src_len -= padding_len;
  		}
  		ptr = NULL;
  	}

  	//设置返回变量
  	jbyteArray bytes = (*env)->NewByteArray(env, src_len);
  	(*env)->SetByteArrayRegion(env, bytes, 0, src_len, (jbyte*) buff);

  	//内存释放
  	free(input);
  	free(buff);

  	return bytes;
  }


JNIEXPORT jstring JNICALL Java_com_jinxiaolu_demo_jni_JniUtil_hmas256Sign
  (JNIEnv *env, jclass jclazz,jstring jstr) {
    char* cstr = (*env)->GetStringUTFChars(env, jstr, 0);
    char *signature[64];
    signs(cstr, signature);
    return (*env)->NewStringUTF(env, signature);
  }


JNIEXPORT jbyteArray JNICALL Java_com_jinxiaolu_demo_jni_JniUtil_encrypt
  (JNIEnv *env, jclass jclazz, jbyteArray jarr){
    return native_aes(env, jarr,ENCRYPT);
  }



JNIEXPORT jbyteArray JNICALL Java_com_jinxiaolu_demo_jni_JniUtil_decrypt
  (JNIEnv *env, jclass jclazz, jbyteArray jarr){
    return native_aes(env, jarr,DECRYPT);
  }

JNIEXPORT jint JNICALL Java_com_jinxiaolu_demo_jni_JniUtil_signatureHashCode
		(JNIEnv *env, jclass jclazz, jobject context){
	//Context的类
	jclass context_clazz = (*env)->GetObjectClass(env, context);
	// 得到 getPackageManager 方法的 ID
	jmethodID methodID_getPackageManager = (*env)->GetMethodID(env, context_clazz,
															   "getPackageManager", "()Landroid/content/pm/PackageManager;");

	// 获得PackageManager对象
	jobject packageManager = (*env)->CallObjectMethod(env, context, methodID_getPackageManager);
//	// 获得 PackageManager 类
	jclass pm_clazz = (*env)->GetObjectClass(env, packageManager);
	// 得到 getPackageInfo 方法的 ID
	jmethodID methodID_pm = (*env)->GetMethodID(env, pm_clazz, "getPackageInfo",
												"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
//
//	// 得到 getPackageName 方法的 ID
	jmethodID methodID_pack = (*env)->GetMethodID(env, context_clazz,
												  "getPackageName", "()Ljava/lang/String;");

	// 获得当前应用的包名
	jstring application_package = (*env)->CallObjectMethod(env, context, methodID_pack);
	const char *str = (*env)->GetStringUTFChars(env, application_package, 0);
//	__android_log_print(ANDROID_LOG_DEBUG, "JNI", "packageName: %s\n", str);

	// 获得PackageInfo
	jobject packageInfo = (*env)->CallObjectMethod(env, packageManager,
												   methodID_pm, application_package, 64);

	jclass packageinfo_clazz = (*env)->GetObjectClass(env, packageInfo);
	jfieldID fieldID_signatures = (*env)->GetFieldID(env, packageinfo_clazz,
													 "signatures", "[Landroid/content/pm/Signature;");
	jobjectArray signature_arr = (jobjectArray)(*env)->GetObjectField(env, packageInfo,
																	  fieldID_signatures);
	//Signature数组中取出第一个元素
	jobject signature = (*env)->GetObjectArrayElement(env, signature_arr, 0);
	//读signature的hashcode
	jclass signature_clazz = (*env)->GetObjectClass(env, signature);
	jmethodID methodID_hashcode = (*env)->GetMethodID(env, signature_clazz,
													  "hashCode", "()I");
	jint hashCode = (*env)->CallIntMethod(env, signature, methodID_hashcode);
//	__android_log_print(ANDROID_LOG_DEBUG, "JNI", "hashcode: %d\n", hashCode);
	return hashCode;
  }