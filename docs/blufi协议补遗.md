对于blufi协议, 能找到的官方文档是 <https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#frame-formats>
其中对于一些重要信息没有描述, 需要从`ESP-IDF`源码中获取信息. 补遗如下:
1. 帧格式中的`序列号`是从0开始的, 每次发送一个新的帧, 序列号加1. 如果没有从0开始, ESP设备端会报错, 返回的type是`0x49`, 即数据帧0x18 subtype(子类型), 这个0x18 subtype在官方文档中是没有定义的.
2. BluFi的加密和校验方式是可以自定义的, 默认的加密是DH/AES128, 校验方式是CRC16, 也是ESP32-C2 官方AT固件中使用的.
2. 校验默认使用CRC-16-CCITT, 大端模式. CRC16的计算是从每一帧的第3个字符开始直到结束, 即不包括类型和帧控制. 计算时, 忽略iv8, CRC从`0取反`开始累计. CRC16的计算和赋值随时注意取值范围不要超过16bit(0xFFFF).

ESP-IDF中, 定义加密和校验函数如下:
```c
// blufi_example_main.c
static esp_blufi_callbacks_t example_callbacks = {
    .event_cb = example_event_callback,
    .negotiate_data_handler = blufi_dh_negotiate_data_handler,
    .encrypt_func = blufi_aes_encrypt,
    .decrypt_func = blufi_aes_decrypt,
    .checksum_func = blufi_crc_checksum,
};
```
ESP-IDF中, 默认加密函数如下:
```c
/*
   The SEC_TYPE_xxx is for self-defined packet data type in the procedure of "BLUFI negotiate key"
   If user use other negotiation procedure to exchange(or generate) key, should redefine the type by yourself.
 */
#define SEC_TYPE_DH_PARAM_LEN   0x00
#define SEC_TYPE_DH_PARAM_DATA  0x01
#define SEC_TYPE_DH_P           0x02
#define SEC_TYPE_DH_G           0x03
#define SEC_TYPE_DH_PUBLIC      0x04

struct blufi_security {
#define DH_SELF_PUB_KEY_LEN     128
#define DH_SELF_PUB_KEY_BIT_LEN (DH_SELF_PUB_KEY_LEN * 8)
    uint8_t  self_public_key[DH_SELF_PUB_KEY_LEN];
#define SHARE_KEY_LEN           128
#define SHARE_KEY_BIT_LEN       (SHARE_KEY_LEN * 8)
    uint8_t  share_key[SHARE_KEY_LEN];
    size_t   share_len;
#define PSK_LEN                 16
    uint8_t  psk[PSK_LEN];
    uint8_t  *dh_param;
    int      dh_param_len;
    uint8_t  iv[16];
    mbedtls_dhm_context dhm;
    mbedtls_aes_context aes;
};
static struct blufi_security *blufi_sec;

void esp_fill_random(void *buf, size_t len)
{
    assert(buf != NULL);
    uint8_t *buf_bytes = (uint8_t *)buf;
    while (len > 0) {
        uint32_t word = esp_random();
        uint32_t to_copy = MIN(sizeof(word), len);
        memcpy(buf_bytes, &word, to_copy);
        buf_bytes += to_copy;
        len -= to_copy;
    }
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    esp_fill_random(output, len);
    return( 0 );
}

int mbedtls_dhm_make_public(mbedtls_dhm_context *ctx, int x_size,
                            unsigned char *output, size_t olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret;

    if (olen < 1 || olen > mbedtls_dhm_get_len(ctx)) {
        return MBEDTLS_ERR_DHM_BAD_INPUT_DATA;
    }

    ret = dhm_make_common(ctx, x_size, f_rng, p_rng);
    if (ret == MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED) {
        return MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED;
    }
    if (ret != 0) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->GX, output, olen));

cleanup:
    if (ret != 0 && ret > -128) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED, ret);
    }
    return ret;
}

size_t mbedtls_dhm_get_len(const mbedtls_dhm_context *ctx)
{
    return mbedtls_mpi_size(&ctx->P);
}
/*
 * Parse the ServerKeyExchange parameters
 */
int mbedtls_dhm_read_params(mbedtls_dhm_context *ctx,
                            unsigned char **p,
                            const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = dhm_read_bignum(&ctx->P,  p, end)) != 0 ||
        (ret = dhm_read_bignum(&ctx->G,  p, end)) != 0 ||
        (ret = dhm_read_bignum(&ctx->GY, p, end)) != 0) {
        return ret;
    }

    if ((ret = dhm_check_range(&ctx->GY, &ctx->P)) != 0) {
        return ret;
    }

    return 0;
}


/*
 * output = MD5( input buffer )
 */
int mbedtls_md5(const unsigned char *input,
                size_t ilen,
                unsigned char output[16])
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md5_context ctx;

    mbedtls_md5_init(&ctx);

    if ((ret = mbedtls_md5_starts(&ctx)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_md5_update(&ctx, input, ilen)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_md5_finish(&ctx, output)) != 0) {
        goto exit;
    }

exit:
    mbedtls_md5_free(&ctx);

    return ret;
}

/*
 * AES key schedule (encryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    uint32_t *RK;

    switch (keybits) {
        case 128: ctx->nr = 10; break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

#if !defined(MBEDTLS_AES_ROM_TABLES)
    if (aes_init_done == 0) {
        aes_gen_tables();
        aes_init_done = 1;
    }
#endif

    ctx->rk_offset = mbedtls_aes_rk_offset(ctx->buf);
    RK = ctx->buf + ctx->rk_offset;

#if defined(MBEDTLS_AESNI_HAVE_CODE)
    if (mbedtls_aesni_has_support(MBEDTLS_AESNI_AES)) {
        return mbedtls_aesni_setkey_enc((unsigned char *) RK, key, keybits);
    }
#endif

#if defined(MBEDTLS_AESCE_HAVE_CODE)
    if (MBEDTLS_AESCE_HAS_SUPPORT()) {
        return mbedtls_aesce_setkey_enc((unsigned char *) RK, key, keybits);
    }
#endif

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
    for (unsigned int i = 0; i < (keybits >> 5); i++) {
        RK[i] = MBEDTLS_GET_UINT32_LE(key, i << 2);
    }

    switch (ctx->nr) {
        case 10:

            for (unsigned int i = 0; i < 10; i++, RK += 4) {
                RK[4]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[3])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[3])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[3])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[3])] << 24);

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 12:

            for (unsigned int i = 0; i < 8; i++, RK += 6) {
                RK[6]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[5])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[5])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[5])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[5])] << 24);

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for (unsigned int i = 0; i < 7; i++, RK += 8) {
                RK[8]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[7])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[7])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[7])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[7])] << 24);

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[11])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[11])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[11])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[11])] << 24);

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
    }

    return 0;
#endif /* !MBEDTLS_AES_USE_HARDWARE_ONLY */
}
#endif /* !MBEDTLS_AES_SETKEY_ENC_ALT */

void blufi_dh_negotiate_data_handler(uint8_t *data, int len, uint8_t **output_data, int *output_len, bool *need_free)
{
    int ret;
    uint8_t type = data[0];

    if (blufi_sec == NULL) {
        BLUFI_ERROR("BLUFI Security is not initialized");
        btc_blufi_report_error(ESP_BLUFI_INIT_SECURITY_ERROR);
        return;
    }

    switch (type) {
    case SEC_TYPE_DH_PARAM_LEN:
        blufi_sec->dh_param_len = ((data[1]<<8)|data[2]);
        if (blufi_sec->dh_param) {
            free(blufi_sec->dh_param);
            blufi_sec->dh_param = NULL;
        }
        blufi_sec->dh_param = (uint8_t *)malloc(blufi_sec->dh_param_len);
        if (blufi_sec->dh_param == NULL) {
            btc_blufi_report_error(ESP_BLUFI_DH_MALLOC_ERROR);
            BLUFI_ERROR("%s, malloc failed\n", __func__);
            return;
        }
        break;
    case SEC_TYPE_DH_PARAM_DATA:{
        if (blufi_sec->dh_param == NULL) {
            BLUFI_ERROR("%s, blufi_sec->dh_param == NULL\n", __func__);
            btc_blufi_report_error(ESP_BLUFI_DH_PARAM_ERROR);
            return;
        }
        uint8_t *param = blufi_sec->dh_param;
        memcpy(blufi_sec->dh_param, &data[1], blufi_sec->dh_param_len);
        ret = mbedtls_dhm_read_params(&blufi_sec->dhm, &param, &param[blufi_sec->dh_param_len]);
        if (ret) {
            BLUFI_ERROR("%s read param failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_READ_PARAM_ERROR);
            return;
        }
        free(blufi_sec->dh_param);
        blufi_sec->dh_param = NULL;

        const int dhm_len = mbedtls_dhm_get_len(&blufi_sec->dhm);
        ret = mbedtls_dhm_make_public(&blufi_sec->dhm, dhm_len, blufi_sec->self_public_key, dhm_len, myrand, NULL);
        if (ret) {
            BLUFI_ERROR("%s make public failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_MAKE_PUBLIC_ERROR);
            return;
        }

        ret = mbedtls_dhm_calc_secret( &blufi_sec->dhm,
                blufi_sec->share_key,
                SHARE_KEY_BIT_LEN,
                &blufi_sec->share_len,
                myrand, NULL);
        if (ret) {
            BLUFI_ERROR("%s mbedtls_dhm_calc_secret failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_DH_PARAM_ERROR);
            return;
        }

        ret = mbedtls_md5(blufi_sec->share_key, blufi_sec->share_len, blufi_sec->psk);

        if (ret) {
            BLUFI_ERROR("%s mbedtls_md5 failed %d\n", __func__, ret);
            btc_blufi_report_error(ESP_BLUFI_CALC_MD5_ERROR);
            return;
        }

        mbedtls_aes_setkey_enc(&blufi_sec->aes, blufi_sec->psk, 128);

        /* alloc output data */
        *output_data = &blufi_sec->self_public_key[0];
        *output_len = dhm_len;
        *need_free = false;

    }
        break;
    case SEC_TYPE_DH_P:
        break;
    case SEC_TYPE_DH_G:
        break;
    case SEC_TYPE_DH_PUBLIC:
        break;
    }
}

int blufi_aes_encrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len)
{
    int ret;
    size_t iv_offset = 0;
    uint8_t iv0[16];

    memcpy(iv0, blufi_sec->iv, sizeof(blufi_sec->iv));
    iv0[0] = iv8;   /* set iv8 as the iv0[0] */

    ret = mbedtls_aes_crypt_cfb128(&blufi_sec->aes, MBEDTLS_AES_ENCRYPT, crypt_len, &iv_offset, iv0, crypt_data, crypt_data);
    if (ret) {
        return -1;
    }

    return crypt_len;
}

int blufi_aes_decrypt(uint8_t iv8, uint8_t *crypt_data, int crypt_len)
{
    int ret;
    size_t iv_offset = 0;
    uint8_t iv0[16];

    memcpy(iv0, blufi_sec->iv, sizeof(blufi_sec->iv));
    iv0[0] = iv8;   /* set iv8 as the iv0[0] */

    ret = mbedtls_aes_crypt_cfb128(&blufi_sec->aes, MBEDTLS_AES_DECRYPT, crypt_len, &iv_offset, iv0, crypt_data, crypt_data);
    if (ret) {
        return -1;
    }

    return crypt_len;
}
```

ESP-IDF中使用的CRC16的计算函数如下:
```c

static uint16_t crc16_be_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129,0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318,0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4, 0xb75b, 0xa77a,0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823, 0xc9cc, 0xd9ed,0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f,0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe,0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290,0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3,0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865,0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54,0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36,0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};


uint16_t esp_rom_crc16_be(uint16_t crc, uint8_t const *buf, uint32_t len){
    unsigned int i;
    crc = ~crc;
    for (i = 0; i < len; i++) {
        crc = crc16_be_table[(crc >> 8)^buf[i]] ^ (crc << 8);
    }
    return ~crc;
}

uint16_t esp_crc16_be(uint16_t crc, uint8_t const *buf, uint32_t len){
    return esp_rom_crc16_be(crc, buf, len);
}

uint16_t blufi_crc_checksum(uint8_t iv8, uint8_t *data, int len){
    /* This iv8 ignore, not used */
    return esp_crc16_be(0, data, len);
}
```

由于官方blufi文档不全面, 所以补充WIFI状态报告消息(数据帧)的完整解析方式. 官方文档说明如下: 
```
- 0xf (b’001111)
     - Wi-Fi 连接状态报告
     - 通知手机 ESP 设备的 Wi-Fi 状态，包括 STA 状态和 SoftAP 状态。用于 STA 设备连接手机或 SoftAP。但是，当手机接收到 Wi-Fi 状态时，除了本帧之外，还可以回复其他帧。
     - data[0] 表示 opmode，包括：

       * 0x00: NULL
       * 0x01: STA
       * 0x02: SoftAP
       * 0x03: SoftAP & STA

       data[1]：STA 设备的连接状态。0x0 表示处于连接状态且获得 IP 地址，0x1 表示处于非连接状态, 0x2 表示处于正在连接状态，0x3 表示处于连接状态但未获得 IP 地址。

       data[2]：SoftAP 的连接状态，即表示有多少 STA 设备已经连接。

       data[3]及后面的数据是按照 SSID/BSSID 格式提供的信息。 如果 Wi-Fi 处于正在连接状态，这里将会包含最大重连次数；如果 Wi-Fi 处于非连接状态，这里将会包含 Wi-Fi 断开连接原因和 RSSI 信息。
```
其中`data[3]`及其以后的数据的定义非常模糊. 实际上`data[3]`可以包括非常丰富的内容, 其格式为多组的状态数据,每组状态数据为:
`1字节类型 + 1字节length + {length}字节的数据`. 
为了更清晰地表明`data[3]`及其以后的数据具体是如何构造的, 下面我引用了设备端构造WIFI状态的完整函数(代码来自ESP-IDF 5.5), WIFI状态报告函数定义及其相关预处理定义如下:

```c

#define BLUFI_TYPE_DATA                                 0x1
#define BLUFI_TYPE_DATA_SUBTYPE_NEG                     0x00
#define BLUFI_TYPE_DATA_SUBTYPE_STA_BSSID               0x01
#define BLUFI_TYPE_DATA_SUBTYPE_STA_SSID                0x02
#define BLUFI_TYPE_DATA_SUBTYPE_STA_PASSWD              0x03
#define BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_SSID             0x04
#define BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_PASSWD           0x05
#define BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_MAX_CONN_NUM     0x06
#define BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_AUTH_MODE        0x07
#define BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_CHANNEL          0x08
#define BLUFI_TYPE_DATA_SUBTYPE_USERNAME                0x09
#define BLUFI_TYPE_DATA_SUBTYPE_CA                      0x0a
#define BLUFI_TYPE_DATA_SUBTYPE_CLIENT_CERT             0x0b
#define BLUFI_TYPE_DATA_SUBTYPE_SERVER_CERT             0x0c
#define BLUFI_TYPE_DATA_SUBTYPE_CLIENT_PRIV_KEY         0x0d
#define BLUFI_TYPE_DATA_SUBTYPE_SERVER_PRIV_KEY         0x0e
#define BLUFI_TYPE_DATA_SUBTYPE_WIFI_REP                0x0f
#define BLUFI_TYPE_DATA_SUBTYPE_REPLY_VERSION           0x10
#define BLUFI_TYPE_DATA_SUBTYPE_WIFI_LIST               0x11
#define BLUFI_TYPE_DATA_SUBTYPE_ERROR_INFO              0x12
#define BLUFI_TYPE_DATA_SUBTYPE_CUSTOM_DATA             0x13
#define BLUFI_TYPE_DATA_SUBTYPE_STA_MAX_CONN_RETRY      0x14
#define BLUFI_TYPE_DATA_SUBTYPE_STA_CONN_END_REASON     0x15
#define BLUFI_TYPE_DATA_SUBTYPE_STA_CONN_RSSI           0x16

/**
  * @brief Wi-Fi disconnection reason codes
  *
  * These reason codes are used to indicate the cause of disconnection.
  */
typedef enum {
    WIFI_REASON_UNSPECIFIED                        = 1,     /**< Unspecified reason */
    WIFI_REASON_AUTH_EXPIRE                        = 2,     /**< Authentication expired */
    WIFI_REASON_AUTH_LEAVE                         = 3,     /**< Deauthentication due to leaving */
    WIFI_REASON_ASSOC_EXPIRE                       = 4,     /**< Deprecated, will be removed in next IDF major release */
    WIFI_REASON_DISASSOC_DUE_TO_INACTIVITY         = 4,     /**< Disassociated due to inactivity */
    WIFI_REASON_ASSOC_TOOMANY                      = 5,     /**< Too many associated stations */
    WIFI_REASON_NOT_AUTHED                         = 6,     /**< Deprecated, will be removed in next IDF major release */
    WIFI_REASON_CLASS2_FRAME_FROM_NONAUTH_STA      = 6,     /**< Class 2 frame received from nonauthenticated STA */
    WIFI_REASON_NOT_ASSOCED                        = 7,     /**< Deprecated, will be removed in next IDF major release */
    WIFI_REASON_CLASS3_FRAME_FROM_NONASSOC_STA     = 7,     /**< Class 3 frame received from nonassociated STA */
    WIFI_REASON_ASSOC_LEAVE                        = 8,     /**< Deassociated due to leaving */
    WIFI_REASON_ASSOC_NOT_AUTHED                   = 9,     /**< Association but not authenticated */
    WIFI_REASON_DISASSOC_PWRCAP_BAD                = 10,    /**< Disassociated due to poor power capability */
    WIFI_REASON_DISASSOC_SUPCHAN_BAD               = 11,    /**< Disassociated due to unsupported channel */
    WIFI_REASON_BSS_TRANSITION_DISASSOC            = 12,    /**< Disassociated due to BSS transition */
    WIFI_REASON_IE_INVALID                         = 13,    /**< Invalid Information Element (IE) */
    WIFI_REASON_MIC_FAILURE                        = 14,    /**< MIC failure */
    WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT             = 15,    /**< 4-way handshake timeout */
    WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT           = 16,    /**< Group key update timeout */
    WIFI_REASON_IE_IN_4WAY_DIFFERS                 = 17,    /**< IE differs in 4-way handshake */
    WIFI_REASON_GROUP_CIPHER_INVALID               = 18,    /**< Invalid group cipher */
    WIFI_REASON_PAIRWISE_CIPHER_INVALID            = 19,    /**< Invalid pairwise cipher */
    WIFI_REASON_AKMP_INVALID                       = 20,    /**< Invalid AKMP */
    WIFI_REASON_UNSUPP_RSN_IE_VERSION              = 21,    /**< Unsupported RSN IE version */
    WIFI_REASON_INVALID_RSN_IE_CAP                 = 22,    /**< Invalid RSN IE capabilities */
    WIFI_REASON_802_1X_AUTH_FAILED                 = 23,    /**< 802.1X authentication failed */
    WIFI_REASON_CIPHER_SUITE_REJECTED              = 24,    /**< Cipher suite rejected */
    WIFI_REASON_TDLS_PEER_UNREACHABLE              = 25,    /**< TDLS peer unreachable */
    WIFI_REASON_TDLS_UNSPECIFIED                   = 26,    /**< TDLS unspecified */
    WIFI_REASON_SSP_REQUESTED_DISASSOC             = 27,    /**< SSP requested disassociation */
    WIFI_REASON_NO_SSP_ROAMING_AGREEMENT           = 28,    /**< No SSP roaming agreement */
    WIFI_REASON_BAD_CIPHER_OR_AKM                  = 29,    /**< Bad cipher or AKM */
    WIFI_REASON_NOT_AUTHORIZED_THIS_LOCATION       = 30,    /**< Not authorized in this location */
    WIFI_REASON_SERVICE_CHANGE_PERCLUDES_TS        = 31,    /**< Service change precludes TS */
    WIFI_REASON_UNSPECIFIED_QOS                    = 32,    /**< Unspecified QoS reason */
    WIFI_REASON_NOT_ENOUGH_BANDWIDTH               = 33,    /**< Not enough bandwidth */
    WIFI_REASON_MISSING_ACKS                       = 34,    /**< Missing ACKs */
    WIFI_REASON_EXCEEDED_TXOP                      = 35,    /**< Exceeded TXOP */
    WIFI_REASON_STA_LEAVING                        = 36,    /**< Station leaving */
    WIFI_REASON_END_BA                             = 37,    /**< End of Block Ack (BA) */
    WIFI_REASON_UNKNOWN_BA                         = 38,    /**< Unknown Block Ack (BA) */
    WIFI_REASON_TIMEOUT                            = 39,    /**< Timeout */
    WIFI_REASON_PEER_INITIATED                     = 46,    /**< Peer initiated disassociation */
    WIFI_REASON_AP_INITIATED                       = 47,    /**< AP initiated disassociation */
    WIFI_REASON_INVALID_FT_ACTION_FRAME_COUNT      = 48,    /**< Invalid FT action frame count */
    WIFI_REASON_INVALID_PMKID                      = 49,    /**< Invalid PMKID */
    WIFI_REASON_INVALID_MDE                        = 50,    /**< Invalid MDE */
    WIFI_REASON_INVALID_FTE                        = 51,    /**< Invalid FTE */
    WIFI_REASON_TRANSMISSION_LINK_ESTABLISH_FAILED = 67,    /**< Transmission link establishment failed */
    WIFI_REASON_ALTERATIVE_CHANNEL_OCCUPIED        = 68,    /**< Alternative channel occupied */

    WIFI_REASON_BEACON_TIMEOUT                     = 200,    /**< Beacon timeout */
    WIFI_REASON_NO_AP_FOUND                        = 201,    /**< No AP found */
    WIFI_REASON_AUTH_FAIL                          = 202,    /**< Authentication failed */
    WIFI_REASON_ASSOC_FAIL                         = 203,    /**< Association failed */
    WIFI_REASON_HANDSHAKE_TIMEOUT                  = 204,    /**< Handshake timeout */
    WIFI_REASON_CONNECTION_FAIL                    = 205,    /**< Connection failed */
    WIFI_REASON_AP_TSF_RESET                       = 206,    /**< AP TSF reset */
    WIFI_REASON_ROAMING                            = 207,    /**< Roaming */
    WIFI_REASON_ASSOC_COMEBACK_TIME_TOO_LONG       = 208,    /**< Association comeback time too long */
    WIFI_REASON_SA_QUERY_TIMEOUT                   = 209,    /**< SA query timeout */
    WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY  = 210,    /**< No AP found with compatible security */
    WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD  = 211,    /**< No AP found in auth mode threshold */
    WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD      = 212,    /**< No AP found in RSSI threshold */
} wifi_err_reason_t;

static void btc_blufi_wifi_conn_report(uint8_t opmode, uint8_t sta_conn_state, uint8_t softap_conn_num, esp_blufi_extra_info_t *info, int info_len)
{
    uint8_t type;
    uint8_t *data;
    int data_len;
    uint8_t *p;

    data_len = info_len + 3;
    p = data = osi_malloc(data_len);
    if (data == NULL) {
        BTC_TRACE_ERROR("%s no mem\n", __func__);
        return;
    }

    type = BLUFI_BUILD_TYPE(BLUFI_TYPE_DATA, BLUFI_TYPE_DATA_SUBTYPE_WIFI_REP);
    *p++ = opmode;
    *p++ = sta_conn_state;
    *p++ = softap_conn_num;

    if (info) {
        if (info->sta_bssid_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_BSSID;
            *p++ = 6;
            memcpy(p, info->sta_bssid, 6);
            p += 6;
        }
        if (info->sta_ssid) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_SSID;
            *p++ = info->sta_ssid_len;
            memcpy(p, info->sta_ssid, info->sta_ssid_len);
            p += info->sta_ssid_len;
        }
        if (info->sta_passwd) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_PASSWD;
            *p++ = info->sta_passwd_len;
            memcpy(p, info->sta_passwd, info->sta_passwd_len);
            p += info->sta_passwd_len;
        }
        if (info->softap_ssid) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_SSID;
            *p++ = info->softap_ssid_len;
            memcpy(p, info->softap_ssid, info->softap_ssid_len);
            p += info->softap_ssid_len;
        }
        if (info->softap_passwd) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_PASSWD;
            *p++ = info->softap_passwd_len;
            memcpy(p, info->softap_passwd, info->softap_passwd_len);
            p += info->softap_passwd_len;
        }
        if (info->softap_authmode_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_AUTH_MODE;
            *p++ = 1;
            *p++ = info->softap_authmode;
        }
        if (info->softap_max_conn_num_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_MAX_CONN_NUM;
            *p++ = 1;
            *p++ = info->softap_max_conn_num;
        }
        if (info->softap_channel_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_SOFTAP_CHANNEL;
            *p++ = 1;
            *p++ = info->softap_channel;
        }
        if (info->sta_max_conn_retry_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_MAX_CONN_RETRY;
            *p++ = 1;
            *p++ = info->sta_max_conn_retry;
        }
        if (info->sta_conn_end_reason_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_CONN_END_REASON;
            *p++ = 1;
            *p++ = info->sta_conn_end_reason;
        }
        if (info->sta_conn_rssi_set) {
            *p++ = BLUFI_TYPE_DATA_SUBTYPE_STA_CONN_RSSI;
            *p++ = 1;
            *p++ = info->sta_conn_rssi;
        }
    }
    if (p - data > data_len) {
        BTC_TRACE_ERROR("%s len error %d %d\n", __func__, (int)(p - data), data_len);
    }

    btc_blufi_send_encap(type, data, data_len);
    osi_free(data);
}
```