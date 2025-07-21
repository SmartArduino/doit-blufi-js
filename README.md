# DOIT BluFi.js SDK
DOIT BluFi.js SDK 是一个基于 JavaScript 的 SDK，用于在微信小程序、Chrome浏览器环境中为乐鑫BluFi设备配网。

乐鑫官方只提供了Android和iOS的SDK。基于微信小程序JavaScript的项目有[xuhongv/BlufiEsp32WeChat](https://github.com/xuhongv/BlufiEsp32WeChat)和[weijian.kang/esp-blufi-for-wx](https://gitee.com/weijian.kang/esp-blufi-for-wx) ，感谢两位大神。但项目久未维护，实际使用中存在一些问题。便与AI大模型合作开发了本项目。

## 实现功能

* 基于BluFi配网，主要参考乐鑫官方的[BluFi文档](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32c2/api-guides/ble/blufi.html)，文档未讲到的部分参考乐鑫官方`ESP-IDF` SDK 源码。
* BluFi设备实时扫描、通过回调实时通知
* 使用async/await语法
* 除了常规的英文和数字WiFi SSID外，还支持支持中文、Emoji字符的SSID配网
* 支持微信小程序
* 支持Chrome浏览器（基于Web Bluetooth API）
* 支持BluFi非加密非校验、非加密校验两种数据传输
* 支持自定义BLE名称前缀
* 支持读取设备端WIFI列表
* 支持向设备端发送自定义消息
* 支持读取设备端发来的自定义消息
* 支持`BluFi.uint8ArrayToString`函数将收到的自定义消息解析为字符串
* 默认使用`wx.logManager`作为日志输出，便于用户反馈问题调试，可通过`enableLogManager`选项禁用
* 为了更好的兼容性，BLE MTU为20字节

## 待实现功能
* 支持加密数据传输

## 使用方法

### 微信小程序
参考`wx-example`项目，在`微信开发者工具`中导入项目并运行。 
微信搜索"Frossky"或扫码可以演示配网功能。
![](docs/xcx_code.jpg)

### Chrome浏览器
参考`h5-example`项目：

1. 确保使用支持Web Bluetooth API的浏览器（Chrome 56+或Edge 79+）
2. 运行启动脚本：
   - Windows: 双击 `h5-example/start-server.bat`
   - Linux/Mac: 运行 `bash h5-example/start-server.sh`
3. 在浏览器中访问 `http://localhost:8000/h5-example/`
4. 注意: Web Bluetooth API需要HTTPS环境（本地开发可使用localhost）

**注意事项：**
- Web Bluetooth API需要HTTPS环境（本地开发可使用localhost）
- 需要用户手动授权蓝牙权限
- 设备扫描需要用户交互触发

### 设备端
设备端可使用乐鑫官方支持BluFi的模组和和支持Blufi的AT固件。包括：
* [ESP32-C2 AT固件](https://docs.espressif.com/projects/esp-at/zh_CN/latest/esp32c2/AT_Binary_Lists/index.html)
* [ESP32-C3 AT固件](https://docs.espressif.com/projects/esp-at/zh_CN/latest/esp32c3/AT_Binary_Lists/index.html)
* [ESP32-C6 AT固件](https://docs.espressif.com/projects/esp-at/zh_CN/latest/esp32c6/AT_Binary_Lists/index.html)
* [ESP32 AT固件](https://docs.espressif.com/projects/esp-at/zh_CN/latest/esp32/AT_Binary_Lists/index.html)

注意，部分模组有多个AT固件，请选择适合的固件。

## API 参考

### 初始化与配置

#### 创建 BluFi 实例

```javascript
const blufi = new BluFi(options);
```

参数说明：
- `options` (Object): 配置选项
  - `devicePrefix` (String): 设备名称前缀，默认为 'BLUFI_'
  - `enableChecksum` (Boolean): 是否启用 CRC16 校验，默认为 false
  - `enableLogManager` (Boolean): 是否使用wx.logManager作为日志输出，默认为 false
  - `onCustomData` (Function): 收到自定义数据时的回调函数，默认为 null

示例：
```javascript
const {BluFi, WIFI_MODE} = require('blufi.js');
const blufi = new BluFi({ 
  devicePrefix: 'BLUFI_',
  enableChecksum: false,
  enableLogManager: false,
  onCustomData: (data) => {
    let dataStr = BluFi.uint8ArrayToString(data); // 微信没有提供字符串转换函数，可使用此函数转换
    console.log('收到自定义数据:', data);
  }
});
```

#### 初始化蓝牙

```javascript
async init()
```

初始化蓝牙模块，必须在使用其他功能前调用。

返回值：
- `Promise<Boolean>`: 初始化成功返回 true，失败返回 false

示例：
```javascript
const initialized = await blufi.init();
if (initialized) {
  console.log('蓝牙初始化成功');
} else {
  console.log('蓝牙初始化失败');
}
```

### 设备扫描与连接

#### 扫描 BluFi 设备

```javascript
async scanDevices(timeout, onDeviceFound)
```

扫描周围的 BluFi 设备。

参数说明：
- `timeout` (Number): 扫描超时时间(毫秒)，默认为 10000ms
- `onDeviceFound` (Function): 发现设备时的回调函数，可选。接收一个设备对象参数

返回值：
- `Promise<Array>`: 扫描到的设备列表

示例：
```javascript
// 方式一：等待扫描完成后获取设备列表
const devices = await blufi.scanDevices(3000);
console.log('扫描到的设备:', devices);

// 方式二：实时获取发现的设备
blufi.scanDevices(3000, (device) => {
  console.log('实时发现设备:', device);
  // 可以在这里更新UI，显示新发现的设备
});
```

#### 连接到 BluFi 设备

```javascript
async connect(deviceId)
```

连接到指定的 BluFi 设备。

参数说明：
- `deviceId` (String): 设备ID，从扫描结果中获取`device.deviceId`

返回值：
- `Promise<Boolean>`: 连接成功返回 true

示例：
```javascript
try {
  await blufi.connect(deviceId);
  console.log('设备连接成功');
} catch (error) {
  console.error('连接设备失败:', error);
}
```

#### 断开连接

```javascript
async disconnect()
```

断开与当前连接的设备的连接。

示例：
```javascript
await blufi.disconnect();
console.log('已断开连接');
```

### WiFi 配置

#### 扫描 WiFi

```javascript
async scanWifi()
```

让设备扫描周围的 WiFi 网络。获取到的WiFi SSID都是设备支持的频段，从而避免连接不支持频段(如5.8G)的WiFi。

返回值：
- `Promise<Array>`: WiFi 列表，每个项目包含 ssid 和 rssi 属性

示例：
```javascript
try {
  const wifiList = await blufi.scanWifi();
  console.log('WiFi 列表:', wifiList);
} catch (error) {
  console.error('扫描 WiFi 失败:', error);
}
```

#### 配置 WiFi 连接

```javascript
async configureWifi(config)
```

配置设备连接到指定的 WiFi 网络。

参数说明：
- `config` (Object): WiFi 配置
  - `ssid` (String): WiFi 的 SSID，可使用`scanWifi()`获取到的`wifiList[i].ssid`
  - `password` (String): WiFi 的密码
  - `mode` (Number): WiFi 模式，默认为 WIFI_MODE.STATION

返回值：
- `Promise<Boolean>`: 配置成功返回 true

示例：
```javascript
try {
  await blufi.configureWifi({
    ssid: 'MyWiFi',
    password: 'password123',
    mode: WIFI_MODE.STATION,
  });
  console.log('WiFi 配置成功');
} catch (error) {
  console.error('WiFi 配置失败:', error);
}
```

### 自定义数据传输

#### 发送自定义数据

```javascript
async sendCustomData(data)
```

向设备发送自定义数据。

参数说明：
- `data` (Uint8Array): 要发送的数据

返回值：
- `Promise<Boolean>`: 发送成功返回 true

示例：
```javascript
try {
  // 将字符串转换为 Uint8Array
  const dataArray = blufi._stringToUint8Array('Hello BluFi');
  
  await blufi.sendCustomData(dataArray);
  console.log('数据发送成功');
} catch (error) {
  console.error('数据发送失败:', error);
}
```

### 常量

#### WiFi 模式

```javascript
const WIFI_MODE = {
  NULL: 0x00,      // 无模式
  STATION: 0x01,   // 站点模式（连接到现有WiFi）
  SOFTAP: 0x02,    // 软AP模式（创建WiFi热点）
  STATIONAP: 0x03  // 同时为站点和软AP模式
};
```

## 交流联系
![](docs/tech-support.png)

        