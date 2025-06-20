**BluFi**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#blufi)

[\[English\]](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c2/api-guides/ble/blufi.html)

**概览**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#id1)

BluFi 是一项基于蓝牙通道的 Wi-Fi 网络配置功能，适用于 ESP32-C2。它通过安全协议将 Wi-Fi 的 SSID、密码等配置信息传输到 ESP32-C2。基于这些信息，ESP32-C2 可进而连接到 AP 或建立 SoftAP。

BluFi 流程的关键部分包括数据的分片、加密以及校验和验证。

用户可按需自定义用于对称加密、非对称加密以及校验的算法。此处，我们采用 DH 算法进行密钥协商，128-AES 算法用于数据加密，CRC16 算法用于校验和验证。

**BluFi 中定义的帧格式**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#frame-formats)

手机应用程序与 ESP32-C2 之间的 BluFi 通信格式定义如下：

帧不分片格式：

| 字段 | 值（字节） |
| --- | --- |
| 类型（最低有效位） | 1 |
| 帧控制 | 1 |
| 序列号 | 1 |
| 数据长度 | 1 |
| 数据 | ${Data Length} |
| 校验（最高有效位） | 2 |

如果使能 **帧控制** 字段中的分片位，则 **数据** 字段中会出现 2 字节的 **内容总长度**。该 **内容总长度** 表示帧的剩余部分的总长度，并用于报告终端需要分配的内存大小。

帧分片格式：

| 字段 | 值（字节） |
| --- | --- |
| 类型（最低有效位） | 1 |
| 帧控制（分片） | 1 |
| 序列号 | 1 |
| 数据长度 | 1 |
| 数据 | 内容总长度：2数据内容长度：${Data Length} - 2 |
| 校验（最高有效位） | 2 |

通常情况下，控制帧不包含数据位，ACK 帧类型除外。

ACK 帧格式 (8 bit)：

| 字段 | 值（字节） |
| --- | --- |
| 类型 - ACK（最低有效位） | 1 |
| 帧控制 | 1 |
| 序列号 | 1 |
| 数据长度 | 1 |
| 数据 | ACK 序列号: 2 |
| 校验（最高有效位） | 2 |

1.  类型字段

**类型** 字段占 1 字节，分为 **类型** 和 **子类型** 两部分。其中，**类型** 占低 2 位，表明该帧为数据帧或是控制帧；**子类型** 占高 6 位，表示此数据帧或者控制帧的具体含义。

*       *   控制帧，暂不进行加密，可校验。
        *   数据帧，可加密，可校验。

1.1 控制帧（二进制：0x0 b’00）

| 控制帧 | 含义 | 解释 | 备注 |
| --- | --- | --- | --- |
| 0x0 (b’000000) | ACK | ACK 帧的数据字段使用回复对象帧的序列值。 | 数据字段占用 1 字节，其序列值与回复对象帧的序列值相同。 |
| 0x1 (b’000001) | 将 ESP 设备设置为安全模式。 | 通知 ESP 设备发送数据时使用的安全模式，在数据发送过程中可多次重置。设置后，将影响后续使用的安全模式。如果不设置，ESP 设备将默认发送不带校验和加密的控制帧和数据帧。从手机到 ESP 设备的数据传输是由这个控制帧控制的。 | 数据字段占一个字节。高 4 位用于控制帧的安全模式设置，低 4 位用于数据帧的安全模式设置。b’0000：无校验、无加密；b’0001：有校验、无加密；b’0010：无校验、有加密；b’0011：有校验、有加密。 |
| 0x2 (b’000010) | 设置 Wi-Fi 的 opmode。 | 该帧包含设置 ESP 设备 Wi-Fi 模式 (opmode) 的设置信息。 | data[0] 用于设置 opmode，包括：0x00: NULL0x01: STA0x02: SoftAP0x03: SoftAP & STA如果设置中包含 AP，请尽量优先设置 AP 模式的 SSID/密码/最大连接数等。 |
| 0x3 (b’000011) | 将 ESP 设备连接至 AP。 | 通知 ESP 设备必要的信息已经发送完毕，可以连接至 AP。 | 不包含数据字段。 |
| 0x4 (b’000100) | 断开 ESP 设备与 AP 的连接。 |  | 不包含数据字段。 |
| 0x5 (b’000101) | 获取 ESP 设备的 Wi-Fi 模式和状态等信息。 |  | 不包含数据字段。ESP 设备收到此控制帧后，会向手机回发一个报告 Wi-Fi 连接状态的帧来告知手机端当前所处的 opmode、连接状态、SSID 等信息。提供给手机端的信息类型由手机上的应用程序决定。 |
| 0x6 (b’000110) | 断开 STA 设备与 SoftAP 的连接（SoftAP 模式）。 |  | data[0~5] 为 STA 设备的 MAC 地址。如有多个 STA 设备，则第二个使用 data[6-11]，依次类推。 |
| 0x7 (b’000111) | 获取版本信息。 |  |  |
| 0x8 (b’001000) | 断开 BLE GATT 连接。 |  | ESP 设备收到该指令后主动断开 BLE GATT 连接。 |
| 0x9 (b’001001) | 获取 Wi-Fi 列表。 | 通知 ESP 设备扫描周围的 Wi-Fi 热点。 | 不包含数据字段。 ESP 设备收到此控制帧后，会向手机回发一个包含 Wi-Fi 热点报告的帧。 |

1.2 数据帧（二进制：0x1 b’01）

| 数据帧 | 含义 | 解释 | 备注 |
| --- | --- | --- | --- |
| 0x0 (b’000000) | 发送协商数据。 | 协商数据会发送到应用层注册的回调函数中。 | 数据的长度取决于数据长度字段。 |
| 0x1 (b’000001) | 发送 STA 模式的 BSSID。 | 在 SSID 隐藏的情况下，发送 STA 设备要连接的 AP 的 BSSID。 | 请参考备注 1。 |
| 0x2 (b’000010) | 发送 STA 模式的 SSID | 发送 STA 设备要连接的 AP 的 SSID。 | 请参考备注 1。 |
| 0x3 (b’000011) | 发送 STA 模式的密码。 | 发送 STA 设备要连接的 AP 的密码。 | 请参考备注 1。 |
| 0x4 (b’000100) | 发送 SoftAP 模式的 SSID。 |  | 请参考备注 1。 |
| 0x5 (b’000101) | 发送 SoftAPmode 模式的密码。 |  | 请参考备注 1。 |
| 0x6 (b’000110) | 设置 SoftAPmode 模式的最大连接数。 |  | data[0] 为连接数的值，范围从 1 到 4。当传输方向是 ESP 设备到手机时，表示向手机端提供所需信息。 |
| 0x7 (b’000111) | 设置 SoftAP 的认证模式。 |  | data[0] 包括：0x00: OPEN0x01: WEP0x02: WPA_PSK0x03: WPA2_PSK0x04: WPA_WPA2_PSK若传输方向是从 ESP 设备到手机，则表示向手机端提供所需信息。 |
| 0x8 (b’001000) | 设置 SoftAP 模式的通道数量。 |  | data[0] 代表支持的通道的数量，范围从 1 到 14。若传输方向是从 ESP 设备到手机，则表示向手机端提供所需信息。 |
| 0x9 (b’001001) | 用户名 | 在进行企业级加密时提供 GATT 客户端的用户名。 | 数据的长度取决于数据长度字段。 |
| 0xa (b’001010) | CA 认证 | 在进行企业级加密时提供 CA 认证。 | 请参考备注 2。 |
| 0xb (b’001011) | 客户端认证 | 在进行企业级加密时提供客户端认证。是否包含私钥，取决于认证的内容。 | 请参考备注 2。 |
| 0xc (b’001100) | 服务端认证 | 在进行企业级加密时提供服务端认证。是否包含私钥，取决于认证的内容。 | 请参考备注 2。 |
| 0xd (b’001101) | 客户端私钥 | 在进行企业级加密时提供客户端私钥。 | 请参考备注 2。 |
| 0xe (b’001110) | 服务端私钥 | 在进行企业级加密时提供服务端私钥。 | 请参考备注 2。 |
| 0xf (b’001111) | Wi-Fi 连接状态报告 | 通知手机 ESP 设备的 Wi-Fi 状态，包括 STA 状态和 SoftAP 状态。用于 STA 设备连接手机或 SoftAP。但是，当手机接收到 Wi-Fi 状态时，除了本帧之外，还可以回复其他帧。 | data[0] 表示 opmode，包括：0x00: NULL 0x01: STA 0x02: SoftAP 0x03: SoftAP & STA; data[1]：STA 设备的连接状态。0x0 表示处于连接状态且获得 IP 地址，0x1 表示处于非连接状态, 0x2 表示处于正在连接状态，0x3 表示处于连接状态但未获得 IP 地址。data[2]：SoftAP 的连接状态，即表示有多少 STA 设备已经连接。data[3]及后面的数据是按照 SSID/BSSID 格式提供的信息。 如果 Wi-Fi 处于正在连接状态，这里将会包含最大重连次数；如果 Wi-Fi 处于非连接状态，这里将会包含 Wi-Fi 断开连接原因和 RSSI 信息。 |
| 0x10 (b’010000) | 版本 |  | data[0]= 主版本data[1]= 子版本 |
| 0x11 (b’010001) | Wi-Fi 热点列表 | 将 Wi-Fi 热点列表发送给 ESP 设备 | 数据帧的格式为 Length + RSSI + SSID。数据较长时可分片发送。 |
| 0x12 (b’010010) | 报告异常 | 通知手机 BluFi 过程出现异常 | 0x00: sequence error0x01: checksum error0x02: decrypt error0x03: encrypt error0x04: init security error0x05: dh malloc error0x06: dh param error0x07: read param error0x08: make public error0x09: data format error0x0a: calculate MD5 error0x0b: Wi-Fi scan error |
| 0x13 (b’010011) | 自定义数据 | 用户发送或者接收自定义数据。 | 数据较长时可分片发送。 |
| 0x14 (b’010100) | 设置最大 Wi-Fi 重连次数。 |  | data[0] 表示 Wi-Fi 最大重连次数。 |
| 0x15 (b’010101) | 设置 Wi-Fi 连接失败原因。 |  | data[0] 表示 Wi-Fi 连接失败原因，它的类型应该和 wifi_err_reason_t 一致。 |
| 0x16 (b’010110) | 设置 Wi-Fi 连接失败的 RSSI 。 |  | data[0] 表示在 Wi-Fi 连接失败时的 RSSI。 如果在连接结束时没有有意义的 RSSI ， 这个值应该为一个无意义值 -128。 |

**备注**

*   备注 1: 数据的长度取决于数据长度字段。若传输方向是从 ESP 设备到手机，则表示向手机端提供所需信息。
*   备注 2: 数据的长度取决于数据长度字段。如果数据长度不够，该帧可用分片。

1.  Frame Control

帧控制字段，占 1 字节，每个位表示不同含义。

| 位 | 含义 |
| --- | --- |
| 0x01 | 表示帧是否加密。1 表示加密。0 表示未加密。该帧的加密部分包括数据字段加密之前的完整明文数据（不包括校验部分）。控制帧暂不加密，故控制帧此位为 0。 |
| 0x02 | 该数据字段表示帧尾是否包含校验位，如 SHA1、MD5、CRC 等。该数据字段包含序列、数据长度以及明文。控制帧和数据帧都可以选择包含或不包含校验位。 |
| 0x04 | 表示数据方向。0 表示传输方向是从手机到 ESP 设备。1 表示传输方向是从 ESP 设备到手机。 |
| 0x08 | 表示是否要求对方回复 ACK。0 表示不要求回复 ACK。1 表示要求回复 ACK。 |
| 0x10 | 表示是否有后续的数据分片。0 表示此帧没有后续数据分片。1 表示还有后续数据分片，用来传输较长的数据。对于分片帧，在数据字段的前两个字节中，会给定当前内容部分和随后内容部分的总长度（即最大支持 64 K 的数据内容）。 |
| 0x10~0x80 | 保留 |

1.  序列控制

序列控制字段。帧发送时，无论帧的类型是什么，序列都会自动加 1，用来防止重放攻击 (Replay Attack)。每次重新连接后，序列清零。

1.  长度

数据字段的长度，不包含校验部分。

1.  数据

对于不同的类型或子类型，数据字段的含义均不同。请参考上方表格。

1.  校验

此字段占两个字节，用来校验序列、数据长度以及明文。

**ESP32-C2 端的安全实现**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#esp32-c2)

1.  数据安全

为了保证 Wi-Fi SSID 和密码的传输过程是安全的，需要使用对称加密算法（例如 AES、DES 等）对报文进行加密。在使用对称加密算法之前，需要使用非对称加密算法（DH、RSA、ECC 等）协商出（或生成出）一个共享密钥。

1.  保证数据完整性

为了保证数据完整性，需要加入校验算法，例如 SHA1、MD5、CRC 等。

1.  身份安全（签名）

某些算法如 RSA 可以保证身份安全。但如 DH 这类的算法，本身不能保证身份安全，需要添加其他算法来签名。

1.  防止重放攻击 (Replay Attack)

添加其到序列字段中，并且在数据校验过程中使用。

在 ESP32-C2 端的代码中，你可以决定和开发如密钥协商等安全处理的流程。手机应用向 ESP32-C2 发送协商数据，数据会传送给应用层处理。如果应用层不处理，可使用 BluFi 提供的 DH 加密算法来协商密钥。

应用层需向 BluFi 注册以下几个与安全相关的函数：

**typedef** void (\*esp\_blufi\_negotiate\_data\_handler\_t)(uint8\_t \*data, int len, uint8\_t \*\*output\_data, int \*output\_len, bool \*need\_free)

该函数用来接收协商期间的正常数据 (normal data)。数据处理完成后，需要将待发送的数据使用 output\_data 和 output\_len 传出。

BluFi 会在调用完 Negotiate\_data\_handler 后，发送 Negotiate\_data\_handler 传出的 output\_data。

这里的两个 “\*” 是因为需要发出去的数据长度未知，所以需要函数自行分配 (malloc) 或者指向全局变量，并告知是否需要通过 NEED\_FREE 释放内存。

**typedef** int (\* esp\_blufi\_encrypt\_func\_t)(uint8\_t iv8, uint8\_t \*crypt\_data, int crypt\_len)

加密和解密的数据长度必须一致。其中 IV8 为帧的 8 位序列，可作为 IV 的某 8 个位来使用。

**typedef** int (\* esp\_blufi\_decrypt\_func\_t)(uint8\_t iv8, uint8\_t \*crypt\_data, int crypt\_len)

加密和解密的数据长度必须一致。其中 IV8 为帧的 8 位序列，可作为 IV 的某 8 个位来使用。

**typedef** uint16\_t (\*esp\_blufi\_checksum\_func\_t)(uint8\_t iv8, uint8\_t \*data, int len)

该函数用来进行校验，返回值为校验的值。BluFi 会使用该函数返回值与帧的校验值进行比较。

**GATT 相关说明**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#gatt)

**UUID**[**ℑ**](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html#uuid)

BluFi Service UUID： 0xFFFF，16 bit

BluFi（手机 > ESP32-C2）特性：0xFF01，主要权限：可写

BluFi（ESP32-C2 > 手机）特性：0xFF02，主要权限：可读可通知