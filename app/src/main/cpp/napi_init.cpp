#include "napi/native_api.h"
#include "openssl/pem.h"
#include "openssl/conf.h"
#include "openssl/x509v3.h"
#include <string>

static napi_value Add(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2] = {nullptr};

    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    napi_valuetype valuetype1;
    napi_typeof(env, args[1], &valuetype1);

    double value0;
    napi_get_value_double(env, args[0], &value0);

    double value1;
    napi_get_value_double(env, args[1], &value1);

    napi_value sum;
    napi_create_double(env, value0 + value1, &sum);

    return sum;
}

/**
 * 生成公私钥对
 * @param env
 * @param info
 * @return
 */
static napi_value NAPI_Global_generateRSA2048KeyPair(napi_env env, napi_callback_info info) {
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIO *pri = NULL, *pub = NULL;
    char *pri_key = NULL, *pub_key = NULL;
    long pri_len, pub_len;
    char *combinedKeys = NULL;
    pkey = EVP_PKEY_new();
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    // 获取私钥
    pri = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(pri, pkey, NULL, NULL, 0, NULL, NULL);
    pri_len = BIO_get_mem_data(pri, &pri_key);
    // 获取公钥
    pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub, pkey);
    pub_len = BIO_get_mem_data(pub, &pub_key);
    // 分配内存并复制数据
    combinedKeys = (char *)malloc(pri_len + pub_len + 1);
    if (combinedKeys) {
        memcpy(combinedKeys, pri_key, pri_len);
        memcpy(combinedKeys + pri_len, pub_key, pub_len);
        combinedKeys[pri_len + pub_len] = '\0';
    }
    // 清理资源
    EVP_PKEY_free(pkey);
    BIO_free(pri);
    BIO_free(pub);
    napi_value napi_result;
    if (napi_ok != napi_create_string_utf8(env, combinedKeys, pri_len + pub_len + 1, &napi_result)) {
        return NULL;
    }
    return napi_result;
}
/**
 * 入参转字符串
 * @param env
 * @param value
 * @return
 */
static std::string value2String(napi_env env, napi_value value) {
    size_t stringSize = 0;
    napi_get_value_string_utf8(env, value, nullptr, 0, &stringSize); // 获取字符串长度
    std::string valueString;
    valueString.resize(stringSize + 1);
    napi_get_value_string_utf8(env, value, &valueString[0], stringSize + 1, &stringSize); // 根据长度传换成字符串
    return valueString;
}
/**
 * 生成CSR
 * @param env
 * @param info
 * @return
 */
static napi_value NAPI_Global_generateCSR(napi_env env, napi_callback_info info) {
    // 解析入参
    size_t argc = 3;
    napi_value args[3] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    napi_value privateKey = args[0];
    napi_value publicKey = args[1];
    napi_value commonName = args[2];
    std::string privateKeyStr = value2String(env, privateKey);
    std::string publicKeyStr = value2String(env, publicKey);
    std::string commonNameStr = value2String(env, commonName);
    // 恢复公私钥对
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    // 从私钥字符串创建 EVP_PKEY
    bio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);
    if (!bio) {
        return NULL;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        // 如果私钥读取失败，尝试从公钥创建
        bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
        if (!bio) {
            return NULL;
        }
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    if (!pkey) {
        return NULL;
    }
    X509_REQ *req = NULL;
    // 创建证书请求
    req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    // 设置公钥
    X509_REQ_set_pubkey(req, pkey);
    // 设置主题名称
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)commonNameStr.c_str(), -1, -1, 0) !=
            1 ||
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"HWYZ", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char *)"MP", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"CN", -1, -1, 0) !=
            1) {
        // 错误处理
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    // 对请求进行签名
    X509_REQ_sign(req, pkey, EVP_sha256());
    // 将 CSR 写入 BIO
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509_REQ(bio, req) != 1) {
        X509_REQ_free(req);
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    // 从 BIO 读取 CSR
    char *buffer;
    long size = BIO_get_mem_data(bio, &buffer);
    std::string csr;
    csr = std::string(buffer, size);
    // 清理资源
    X509_REQ_free(req);
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    napi_value napi_result;
    if (napi_ok != napi_create_string_utf8(env, csr.c_str(), csr.length(), &napi_result)) {
        return NULL;
    }
    return napi_result;
}
EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"add", nullptr, Add, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"generateRSA2048KeyPair", nullptr, NAPI_Global_generateRSA2048KeyPair, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"generateCSR", nullptr, NAPI_Global_generateCSR, nullptr, nullptr, nullptr, napi_default, nullptr}};
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "app",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterAppModule(void) { napi_module_register(&demoModule); }