/**
 * BluFi 微信小程序实现
 * 基于ESP32-C2的BluFi协议
 * Copyright (c) 2025, Jacques Yang. 
 * MIT License.
 */

// 常量定义
const BLUFI_SERVICE_UUID = '0000FFFF-0000-1000-8000-00805F9B34FB';
const BLUFI_CHAR_WRITE_UUID = '0000FF01-0000-1000-8000-00805F9B34FB';
const BLUFI_CHAR_NOTIFY_UUID = '0000FF02-0000-1000-8000-00805F9B34FB';

// BluFi帧类型
const FRAME_TYPE = {
  CTRL: 0x00,
  DATA: 0x01
};

// BluFi控制帧子类型
// BluFi控制帧子类型
const CTRL_SUBTYPE = {
  ACK: 0x00,
  SET_SEC_MODE: 0x01,
  SET_OP_MODE: 0x02,
  CONNECT_WIFI: 0x03,
  DISCONNECT_WIFI: 0x04,
  GET_WIFI_STATUS: 0x05,
  DISCONNECT_STA: 0x06,
  GET_VERSION: 0x07,
  DISCONNECT_BLE: 0x08,
  GET_WIFI_LIST: 0x09
};

// BluFi数据帧子类型
const DATA_SUBTYPE = {
  NEG_DATA: 0x00,
  WIFI_BSSID: 0x01,
  WIFI_SSID: 0x02,
  WIFI_PASSWORD: 0x03,
  SOFTAP_SSID: 0x04,
  SOFTAP_PASSWORD: 0x05,
  SOFTAP_MAX_CONN_NUM: 0x06,
  SOFTAP_AUTH_MODE: 0x07,
  SOFTAP_CHANNEL: 0x08,
  USERNAME: 0x09,
  CA_CERTIFICATION: 0x0A,
  CLIENT_CERTIFICATION: 0x0B,
  SERVER_CERTIFICATION: 0x0C,
  CLIENT_PRIVATE_KEY: 0x0D,
  SERVER_PRIVATE_KEY: 0x0E,
  WIFI_CONNECTION_STATE: 0x0F,
  VERSION: 0x10,
  WIFI_LIST: 0x11,
  ERROR: 0x12,
  CUSTOM_DATA: 0x13,
  MAX_RECONNECT: 0x14,
  WIFI_ERROR_REASON: 0x15,
  WIFI_ERROR_RSSI: 0x16
};

// WiFi模式
const WIFI_MODE = {
  NULL: 0x00,
  STATION: 0x01,
  SOFTAP: 0x02,
  STATIONAP: 0x03
};

// 安全模式
const SEC_MODE = {
  OPEN: 0x00,
  WEP: 0x01,
  WPA_PSK: 0x02,
  WPA2_PSK: 0x03,
  WPA_WPA2_PSK: 0x04,
  WPA2_ENTERPRISE: 0x05,
  WPA3_PSK: 0x06,
  WPA2_WPA3_PSK: 0x07
};

const STATION_CONNECT_STATUS = {
  CONNECTED_AND_GOT_IP: 0x00,
  DISCONNECTED: 0x01,
  CONNECTING: 0x02,
  CONNETED: 0x03,
}

// 安全帧控制位
const FRAME_CTRL_ENCRYPTED = 0x01;    // 加密位
const FRAME_CTRL_CHECKSUM = 0x02;     // 校验和位
const FRAME_CTRL_DATA_DIRECTION = 0x04; // 数据方向位
const FRAME_CTRL_REQUIRE_ACK = 0x08;  // 需要ACK位
const FRAME_CTRL_FRAG = 0x10;         // 分片位

class BluFi {
  /**
   * 创建BluFi实例
   * @param {Object} options - 配置选项
   * @param {String} options.devicePrefix - 设备名称前缀, 默认BLUFI_
   * @param {Boolean} options.enableChecksum - 是否启用CRC16校验, 默认false
   * @param {Boolean} options.enableLogManager - 是否使用wx.logManager作为日志输出, 默认false
   * @param {Function} options.onCustomData - 收到自定义数据时的回调函数, 默认为null
   */
  constructor(options = {}) {
    this.deviceId = null;
    this.serviceId = null;
    this.writeCharId = null;
    this.notifyCharId = null;
    this.connected = false;
    this.isNotifying = false;
    this.encryptionKey = null;
    this.sequence = -1; // 序列号需要初始化为-1, 这样自加后会从0开始, 且必须从0开始, 否则报错
    this.callbacks = {};
    
    // 设备前缀
    this.devicePrefix = options.devicePrefix || 'BLUFI_';
    
    // 日志管理器设置
    this.enableLogManager = options.enableLogManager !== undefined ? options.enableLogManager : false;
    this.logger = this.enableLogManager ? uni.getLogManager() : (options.onLog ?? console);
    
    // 自定义数据回调
    this.callbacks.onCustomData = options.onCustomData || null;
    this.callbacks.onWifiStatusChange = options.onWifiStatusChange || null;
    // 安全相关
    this.securityMode = 0; // 默认无加密无校验
    this.dh = null;
    this.dhPublicKey = null;
    this.dhPrivateKey = null;
    this.devicePublicKey = null;
    this.sharedSecret = null;
    this.encryptionIV = new Uint8Array(16); // AES-128 IV
    this.isEncrypted = false;
    
    // CRC16校验相关
    this.enableChecksum = options.enableChecksum || false; // 是否启用CRC16校验
  }

  /**
   * 初始化蓝牙
   */
  async init() {
    try {
      // 初始化蓝牙模块
      await this._promisify(wx.openBluetoothAdapter);
      this.logger.log('蓝牙初始化成功');
      return true;
    } catch (error) {
      this.logger.warn('蓝牙初始化失败:', error);
      return false;
    }
  }

  /**
   * 扫描BluFi设备
   * @param {Number} timeout - 扫描超时时间(ms)
   * @param {Function} onDeviceFound - 发现设备时的回调函数
   * @returns {Promise<Array>} - 扫描到的设备列表
   */
  async scanDevices(timeout = 10000, onDeviceFound = null) {
    try {
      // 创建一个设备映射，用于跟踪已发现的设备
      const deviceMap = new Map();
      
      // 开始搜寻附近的蓝牙外围设备
      await this._promisify(wx.startBluetoothDevicesDiscovery, {
        // services: [BLUFI_SERVICE_UUID],
        allowDuplicatesKey: true,
      });
      
      this.logger.log('开始扫描设备');
      
      // 如果提供了回调函数，设置蓝牙设备发现事件监听器
      if (onDeviceFound) {
        wx.onBluetoothDeviceFound((res) => {
          res.devices.forEach(device => {
            // 检查是否为目标设备
            if (device.name && device.name.includes(this.devicePrefix)) {
              this.logger.log('found dev', device.deviceId)
              // 检查是否已经发现过该设备
              if (!deviceMap.has(device.deviceId)) {
                deviceMap.set(device.deviceId, device);
                // 调用回调函数，通知发现了新设备
                onDeviceFound(device);
              }
            }
          });
        });
      }
      
      // 等待指定时间
      await new Promise(resolve => setTimeout(resolve, timeout));
      
      // 停止监听蓝牙设备发现事件
      if (onDeviceFound) {
        wx.offBluetoothDeviceFound();
      }
      
      // 获取在蓝牙模块生效期间所有已发现的蓝牙设备
      const res = await this._promisify(wx.getBluetoothDevices);
      this.logger.log('scanDevices', res);
      
      // 停止搜寻
      await this._promisify(wx.stopBluetoothDevicesDiscovery);
      
      // 过滤出ESP32设备
      const devices = res.devices.filter(device => 
        device.name && device.name.includes(this.devicePrefix)
      );
      
      this.logger.log('扫描到的设备:', devices);
      return devices;
    } catch (error) {
      // 确保在出错时也停止监听
      if (onDeviceFound) {
        wx.offBluetoothDeviceFound();
      }
      
      this.logger.warn('扫描设备失败:', error);
      throw error;
    }
  }

  /**
   * 连接到BluFi设备
   * @param {String} deviceId - 设备ID
   */
  async connect(deviceId) {
    try {
      this.deviceId = deviceId;
      
      // 连接设备
      await this._promisify(wx.createBLEConnection, { deviceId });
      this.logger.log('设备连接成功');
      
      // 获取服务
      const servicesRes = await this._promisify(wx.getBLEDeviceServices, { deviceId });
      this.logger.log('获取服务列表:', servicesRes.services);
      
      // 查找BluFi服务
      const service = servicesRes.services.find(s => s.uuid.toUpperCase() === BLUFI_SERVICE_UUID);
      if (!service) {
        throw new Error('未找到BluFi服务');
      }
      this.serviceId = service.uuid;
      
      // 获取特征值
      const charsRes = await this._promisify(wx.getBLEDeviceCharacteristics, {
        deviceId,
        serviceId: this.serviceId
      });
      this.logger.log('获取特征值列表:', charsRes.characteristics);
      
      // 查找写特征值和通知特征值
      const writeChar = charsRes.characteristics.find(c => c.uuid.toUpperCase() === BLUFI_CHAR_WRITE_UUID);
      const notifyChar = charsRes.characteristics.find(c => c.uuid.toUpperCase() === BLUFI_CHAR_NOTIFY_UUID);
      
      if (!writeChar || !notifyChar) {
        throw new Error('未找到必要的BluFi特征值');
      }
      
      this.writeCharId = writeChar.uuid;
      this.notifyCharId = notifyChar.uuid;
      this.sequence = -1; // 初始化序列号
      
      // 启用通知
      await this._enableNotify();
      
      // 初始化安全连接
      await this._initSecurity();

      this.connected = true;
      return true;
    } catch (error) {
      this.logger.warn('连接设备失败:', error);
      this.disconnect();
      throw error;
    }
  }
/**
 * 初始化安全连接
 * @private
 */
async _initSecurity() {
  try {
    this.logger.log('初始化安全连接');
    
    // 根据是否启用校验设置安全模式
    // 高4位用于控制帧的安全模式设置，低4位用于数据帧的安全模式设置
    // b'0000：无校验、无加密；b'0001：有校验、无加密；b'0010：无校验、有加密；b'0011：有校验、有加密
    let secMode = 0x00; // 默认无校验无加密
    
    if (this.enableChecksum) {
      secMode |= 0b00010001; // 控制帧和数据帧打开校验
    }
    
    // 设置安全模式
    await this._sendCtrlFrame(CTRL_SUBTYPE.SET_SEC_MODE, new Uint8Array([secMode]));
    
    return true;
  } catch (error) {
    this.logger.warn('初始化安全连接失败:', error);
    throw error;
  }
}


  /**
   * 断开连接
   */
  async disconnect() {
    if (this.deviceId) {
      try {
        if (this.isNotifying) {
          await this._promisify(wx.notifyBLECharacteristicValueChange, {
            deviceId: this.deviceId,
            serviceId: this.serviceId,
            characteristicId: this.notifyCharId,
            state: false
          });
          this.isNotifying = false;
        }
        
        await this._promisify(wx.closeBLEConnection, { deviceId: this.deviceId });
        this.logger.log('设备已断开连接');
      } catch (error) {
        this.logger.warn('断开连接失败:', error);
      } finally {
        this.deviceId = null;
        this.serviceId = null;
        this.writeCharId = null;
        this.notifyCharId = null;
        this.connected = false;
        this.isEncrypted = false;
        this.sharedSecret = null;
        this.devicePublicKey = null;
      }
    }
  }

  /**
   * 配置WiFi
   * @param {Object} config - WiFi配置
   * @param {String} config.ssid - WiFi SSID
   * @param {String} config.password - WiFi密码
   * @param {Number} config.mode - WiFi模式
   */
  async configureWifi(config) {
    if (!this.connected) {
      throw new Error('设备未连接');
    }
    
    try {
      // 设置操作模式
      await this._sendCtrlFrame(CTRL_SUBTYPE.SET_OP_MODE, new Uint8Array([config.mode || WIFI_MODE.STATION]));
      
      // 发送SSID
      const ssidData = this._stringToUint8Array(config.ssid);
      await this._sendDataFrame(DATA_SUBTYPE.WIFI_SSID, ssidData);
      
      // 发送密码
      if (config.password) {
        const passwordData = this._stringToUint8Array(config.password);
        await this._sendDataFrame(DATA_SUBTYPE.WIFI_PASSWORD, passwordData);
      }
      
      // 连接WiFi
      await this._sendCtrlFrame(CTRL_SUBTYPE.CONNECT_WIFI, new Uint8Array([]));
      
      return true;
    } catch (error) {
      this.logger.warn('配置WiFi失败:', error);
      throw error;
    }
  }

  /**
   * 获取WiFi状态
   */
  async getWifiStatus() {
    if (!this.connected) {
      throw new Error('设备未连接');
    }
    
    try {
      return new Promise((resolve, reject) => {
        // 设置回调
        this.callbacks._wifiStatus = (data) => {
          resolve(data);
          delete this.callbacks._wifiStatus;
        };
        
        // 发送获取WiFi状态请求
        this._sendCtrlFrame(CTRL_SUBTYPE.GET_WIFI_STATUS, new Uint8Array([]))
          .catch(err => {
            delete this.callbacks._wifiStatus;
            reject(err);
          });
        
        // 设置超时
        setTimeout(() => {
          if (this.callbacks._wifiStatus) {
            delete this.callbacks._wifiStatus;
            reject(new Error('获取WiFi状态超时'));
          }
        }, 10000);
      });
    } catch (error) {
      this.logger.warn('获取WiFi状态失败:', error);
      throw error;
    }
  }

  /**
   * 扫描WiFi网络
   */
  async scanWifi(timeout=6000) {
    if (!this.connected) {
      throw new Error('设备未连接');
    }
    
    try {
      return new Promise((resolve, reject) => {
        const wifiList = [];
        
        // 设置回调
        this.callbacks.onWifiListReceived = (data) => {
          wifiList.push(...data);
          const result = wifiList.slice(); // 复制当前列表
          resolve(result);
        };
        
        // 发送扫描请求
        this._sendCtrlFrame(CTRL_SUBTYPE.GET_WIFI_LIST, new Uint8Array([]))
          .catch(err => {
            delete this.callbacks.onWifiListReceived;
            reject(err);
          });
        
        // 设置超时，在超时后返回已收集的WiFi列表
        setTimeout(() => {
          const result = wifiList.slice(); // 复制当前列表
          delete this.callbacks.onWifiListReceived;
          resolve(result);
        }, timeout); 
      });
    } catch (error) {
      this.logger.warn('扫描WiFi失败:', error);
      throw error;
    }
  }

  /**
   * 发送自定义字符串
   * @param {string} str 自定义字符串
   */
  async sendCustomStr(str){
    await this.sendCustomData(this._stringToUint8Array(str))
  }

  /**
   * 发送自定义数据
   * @param {Uint8Array} data - 自定义数据
   */
  async sendCustomData(data) {
    if (!this.connected) {
      throw new Error('设备未连接');
    }
    
    try {
      await this._sendDataFrame(DATA_SUBTYPE.CUSTOM_DATA, data);
      return true;
    } catch (error) {
      this.logger.warn('发送自定义数据失败:', error);
      throw error;
    }
  }

  /**
   * 启用特征值通知
   * @private
   */
  async _enableNotify() {
    try {
      // 启用通知
      await this._promisify(wx.notifyBLECharacteristicValueChange, {
        deviceId: this.deviceId,
        serviceId: this.serviceId,
        characteristicId: this.notifyCharId,
        state: true
      });
      
      this.isNotifying = true;
      this.logger.log('通知已启用');
      
      // 监听特征值变化
      wx.onBLECharacteristicValueChange(this._onCharacteristicValueChange.bind(this));
      
      return true;
    } catch (error) {
      this.logger.warn('启用通知失败:', error);
      throw error;
    }
  }

  /**
   * 特征值变化回调
   * @private
   */
  _onCharacteristicValueChange(res) {
    if (res.characteristicId.toUpperCase() === this.notifyCharId.toUpperCase()) {
      const data = new Uint8Array(res.value);
      this.logger.log('收到数据:', this._arrayBufferToHex(res.value));
      
      this._parseResponse(data);
    }
  }

  /**
   * 解析响应数据
   * @private
   */
  _parseResponse(data) {
    try {
      const frameType = data[0] & 0x03;
      const frameSubType = (data[0] >> 2) & 0x3F;
      const frameCtrl = data[1];
      const sequence = data[2];
      const dataLen = data[3];
      
      // 检查是否为分片数据或者是否有未完成的分片缓存
      const cacheKey = `${frameType}_${frameSubType}`;
      const hasFragmentCache = this.fragmentCache && this.fragmentCache[cacheKey];
      
      if ((frameCtrl & FRAME_CTRL_FRAG) || hasFragmentCache) {
        // 处理分片数据
        return this._handleFragmentedData(data, frameType, frameSubType, frameCtrl, sequence, dataLen);
      }
      
      // 检查是否需要解密
      let payload;
      if (frameCtrl & FRAME_CTRL_ENCRYPTED && this.isEncrypted) {
        // 解密数据
        const encryptedData = data.slice(4, 4 + dataLen);
        payload = this._decrypt(encryptedData, sequence);
      } else {
        payload = data.slice(4, 4 + dataLen);
      }
      
      // 检查校验和
      if (frameCtrl & FRAME_CTRL_CHECKSUM) {
        const checksumPos = 4 + dataLen;
        if (data.length < checksumPos + 2) {
          this.logger.warn('数据长度不足以包含校验和');
          return;
        }
        
        const receivedChecksum = (data[checksumPos + 1] << 8) | data[checksumPos];
        const calculatedChecksum = this._calculateChecksum(data.subarray(2, checksumPos));
        
        if (receivedChecksum !== calculatedChecksum) {
          this.logger.warn('校验和不匹配:', receivedChecksum, calculatedChecksum);
          return;
        }
      }
      
      // 处理不同类型的帧
      this._processFrame(frameType, frameSubType, payload);
    } catch (error) {
      this.logger.warn('解析响应数据失败:', error);
    }
  }

  /**
   * 处理分片数据
   * @private
   */
  _handleFragmentedData(data, frameType, frameSubType, frameCtrl, sequence, dataLen) {
    try {
      // 初始化分片缓存对象（如果不存在）
      if (!this.fragmentCache) {
        this.fragmentCache = {};
      }
      
      // 获取分片数据
      let payload = data.slice(4, 4 + dataLen);
      
      // 检查是否需要解密
      if (frameCtrl & FRAME_CTRL_ENCRYPTED && this.isEncrypted) {
        payload = this._decrypt(payload, sequence);
      }
      
      const cacheKey = `${frameType}_${frameSubType}`;
      
      // 判断是否是第一个分片
      if (frameCtrl & FRAME_CTRL_FRAG && !this.fragmentCache[cacheKey]) {
        // 从分片数据的前两个字节获取内容总长度
        const totalLen = (payload[1] << 8) | payload[0];
        const fragmentData = payload.slice(2);
        
        // 创建新的分片缓存
        this.fragmentCache[cacheKey] = {
          totalLen: totalLen,
          receivedLen: fragmentData.length,
          data: new Uint8Array(totalLen),
          frameType: frameType,
          frameSubType: frameSubType
        };
        
        // 复制第一个分片的数据
        this.fragmentCache[cacheKey].data.set(fragmentData, 0);
        this.logger.log(`接收第一个分片数据: ${fragmentData.length}/${totalLen}`);
      } 
      // 处理中间分片或最后一个分片
      else if (this.fragmentCache[cacheKey]) {
        const cache = this.fragmentCache[cacheKey];
        let fragmentData;
        
        // 如果是中间分片，数据从第三个字节开始
        if (frameCtrl & FRAME_CTRL_FRAG) {
          fragmentData = payload.slice(2);
        } 
        // 如果是最后一个分片（没有FRAG标志），也从第一个字节开始
        else {
          fragmentData = payload;
        }
        
        // 追加分片数据
        cache.data.set(fragmentData, cache.receivedLen);
        cache.receivedLen += fragmentData.length;
        
        this.logger.log(`接收分片数据: ${cache.receivedLen}/${cache.totalLen}`);
        
        // 检查是否接收完所有分片
        if (cache.receivedLen >= cache.totalLen || !(frameCtrl & FRAME_CTRL_FRAG)) {
          this.logger.log(`所有分片数据接收完毕，总长度: ${cache.totalLen}`);
          
          // 处理完整的数据
          const completeData = cache.data.slice(0, cache.totalLen);
          this._processFrame(cache.frameType, cache.frameSubType, completeData);
          
          // 清除缓存
          delete this.fragmentCache[cacheKey];
        }
      } 
      // 如果没有缓存但收到了没有FRAG标志的数据包，直接处理
      else {
        this._processFrame(frameType, frameSubType, payload);
      }
    } catch (error) {
      this.logger.warn('处理分片数据失败:', error);
    }
  }

  /**
   * 处理完整的帧数据
   * @private
   */
  _processFrame(frameType, frameSubType, payload) {
    if (frameType === FRAME_TYPE.CTRL) {
      switch (frameSubType) {
        case CTRL_SUBTYPE.ACK:
          this.logger.log('收到ACK');
          break;
        default:
          this.logger.log('未处理的控制帧子类型:', frameSubType);
      }
    } else if (frameType === FRAME_TYPE.DATA) {
      switch (frameSubType) {
        case DATA_SUBTYPE.WIFI_SSID:
          const ssid = this.constructor.uint8ArrayToString(payload);
          this.logger.log('WiFi SSID:', ssid);
          break;
        case DATA_SUBTYPE.CUSTOM_DATA:
          this.logger.log('自定义数据:', payload);
          if (this.callbacks.onCustomData) {
            this.callbacks.onCustomData(payload);
          }
          break;
        case DATA_SUBTYPE.NEG_DATA:
          this.logger.log('协商数据:', payload);
          break;
        case DATA_SUBTYPE.WIFI_LIST:
          this.logger.log('WiFi列表:', payload, this.callbacks);
          if (this.callbacks.onWifiListReceived) {
            // 解析WiFi列表数据
            const wifiInfo = this._parseWifiListData(payload); 
            this.callbacks.onWifiListReceived(wifiInfo);
            this.logger.log('wifiInfo', wifiInfo);
          }
          break;
        case DATA_SUBTYPE.WIFI_CONNECTION_STATE:
          this.logger.log('WiFi连接状态:', payload);
          if (this.callbacks.onWifiStatusChange) {
            // 解析WiFi状态数据
            const statusInfo = this._parseWifiStatusData(payload);
            this.callbacks.onWifiStatusChange(statusInfo);
          }
          break;
        default:
          this.logger.log('未处理的数据帧子类型:', frameSubType);
      }
    }
  }

  /**
   * 解析WiFi列表数据
   * @private
   */
  _parseWifiListData(data) {
    try {
      let offset = 0;
      const result = [];
      const ssidMap = {}; // 用于存储已解析的SSID, 避免重复解析
      
      while (offset < data.length) {
        const ssidLen = data[offset++];
        if (offset + ssidLen > data.length) break;
        
        const rssi = data[offset++];
        
        // 提取SSID字节数组
        const ssidBytes = data.slice(offset, offset + ssidLen - 1);
        
        // 使用已有的字符串转换方法
        const ssid = this.constructor.uint8ArrayToString(ssidBytes);
        
        offset += ssidLen - 1;
        if(ssidMap[ssid]) continue; // 跳过已解析的SSID
        ssidMap[ssid] = true;
        result.push({
          ssid,
          rssi
        });
      }
      
      return result;
    } catch (error) {
      this.logger.warn('解析WiFi列表数据失败:', error);
      return [];
    }
  }

  /**
   * 解析WiFi状态数据
   * @private
   */
  _parseWifiStatusData(data) {
    try {
      if (data.length < 3) return null;
      
      const opMode = data[0];
      const staConnStatus = data[1];
      const softApConnNum = data[2];
      
      let ssid = '';
      if (data.length > 3) {
        ssid = this.constructor.uint8ArrayToString(data.slice(3));
      }
      
      return {
        opMode,
        staConnStatus,
        softApConnNum,
        ssid
      };
    } catch (error) {
      this.logger.warn('解析WiFi状态数据失败:', error);
      return null;
    }
  }

  /**
   * 加密数据
   * @private
   */
  _encrypt(data, sequence) {
    if (!this.isEncrypted || !this.sharedSecret) {
      return data;
    }
    
    try {
      // 使用微信小程序的加密API
      // 注意：这里简化处理，实际应该使用AES-128-CFB模式
      // 由于微信小程序环境限制，这里使用一个简单的XOR加密作为示例
      const key = new Uint8Array(this.sharedSecret);
      const iv = new Uint8Array(this.encryptionIV);
      iv[0] = sequence; // 使用序列号作为IV的一部分
      
      const encrypted = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        encrypted[i] = data[i] ^ key[i % key.length] ^ iv[i % iv.length];
      }
      
      return encrypted;
    } catch (error) {
      this.logger.warn('加密数据失败:', error);
      return data;
    }
  }

  /**
   * 解密数据
   * @private
   */
  _decrypt(data, sequence) {
    // 解密与加密使用相同算法
    return this._encrypt(data, sequence);
  }

  /**
   * 发送控制帧
   * @private
   */
  async _sendCtrlFrame(subType, data) {
    // 检查数据长度是否需要分片
    const MAX_FRAME_SIZE = 18; // BLE限制每次发送不超过18字节
    const HEADER_SIZE = 4; // 类型(1) + 帧控制(1) + 序列号(1) + 数据长度(1)
    const CHECKSUM_SIZE = this.enableChecksum? 2: 0; // 校验和(2)
    const MAX_DATA_SIZE = MAX_FRAME_SIZE - HEADER_SIZE - CHECKSUM_SIZE; // 最大数据长度
    
    if (!data || data.length <= MAX_DATA_SIZE) {
      // 数据长度不超过最大限制，直接发送
      const frame = this._buildFrame(FRAME_TYPE.CTRL, subType, data);
      return this._writeData(frame);
    } else {
      // 数据需要分片发送
      this.logger.log(`数据长度超过${MAX_DATA_SIZE}字节，需要分片发送`);
      
      // 计算分片数量
      const totalDataLength = data.length;
      const firstFrameDataSize = MAX_DATA_SIZE - 2; // 第一个分片需要减去2字节的内容总长度
      const middleFrameDataSize = MAX_DATA_SIZE - 2; // 中间分片也需要减去2字节的内容总长度
      
      // 计算需要多少个分片
      let remainingData = totalDataLength;
      let numFragments = 1; // 至少有一个分片
      
      remainingData -= firstFrameDataSize;
      while (remainingData > 0) {
        remainingData -= middleFrameDataSize;
        numFragments++;
      }
      
      this.logger.log(`总数据长度: ${totalDataLength}字节，需要${numFragments}个分片`);
      
      // 发送所有分片
      let offset = 0;
      let fragmentIndex = 0;
      let result;
      
      while (offset < totalDataLength) {
        const isLastFragment = (fragmentIndex === numFragments - 1);
        const isFirstFragment = (fragmentIndex === 0);
        
        // 确定当前分片的数据大小
        let currentFragmentSize;
        if (isFirstFragment) {
          currentFragmentSize = Math.min(firstFrameDataSize, totalDataLength);
        } else {
          currentFragmentSize = Math.min(middleFrameDataSize, totalDataLength - offset);
        }
        
        // 准备当前分片的数据
        let fragmentData;
        if (!isLastFragment) {
          // 非最后一个分片，需要添加内容总长度
          fragmentData = new Uint8Array(currentFragmentSize + 2);
          // 设置内容总长度（2字节，小端序）
          fragmentData[0] = totalDataLength & 0xFF;
          fragmentData[1] = (totalDataLength >> 8) & 0xFF;
          // 复制数据
          fragmentData.set(data.slice(offset, offset + currentFragmentSize), 2);
        } else {
          // 最后一个分片，直接使用剩余数据
          fragmentData = data.slice(offset);
        }
        
        // 设置帧控制标志
        let frameCtrl = 0;
        if (!isLastFragment) {
          // 非最后一个分片，设置分片标志
          frameCtrl |= FRAME_CTRL_FRAG;
        }
        
        // 构建并发送当前分片
        const frame = this._buildFrameWithCtrl(FRAME_TYPE.CTRL, subType, fragmentData, frameCtrl);
        result = await this._writeData(frame);
        
        // 更新偏移量和分片索引
        if (isFirstFragment) {
          offset += firstFrameDataSize;
        } else {
          offset += middleFrameDataSize;
        }
        fragmentIndex++;
        
        // 添加一些延迟，避免发送过快导致接收方处理不过来
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      return result;
    }
  }

  /**
   * 发送数据帧
   * @private
   */
  async _sendDataFrame(subType, data) {
    // 检查数据长度是否需要分片
    const MAX_FRAME_SIZE = 18; // BLE限制每次发送不超过18字节
    const HEADER_SIZE = 4; // 类型(1) + 帧控制(1) + 序列号(1) + 数据长度(1)
    const CHECKSUM_SIZE = this.enableChecksum? 2: 0; // 校验和(2)
    const MAX_DATA_SIZE = MAX_FRAME_SIZE - HEADER_SIZE - CHECKSUM_SIZE; // 最大数据长度
    
    if (!data || data.length <= MAX_DATA_SIZE) {
      // 数据长度不超过最大限制，直接发送
      const frame = this._buildFrame(FRAME_TYPE.DATA, subType, data);
      return this._writeData(frame);
    } else {
      // 数据需要分片发送
      this.logger.log(`数据长度超过${MAX_DATA_SIZE}字节，需要分片发送`);
      
      // 计算分片数量
      const totalDataLength = data.length;
      const firstFrameDataSize = MAX_DATA_SIZE - 2; // 第一个分片需要减去2字节的内容总长度
      const middleFrameDataSize = MAX_DATA_SIZE - 2; // 中间分片也需要减去2字节的内容总长度
      
      // 计算需要多少个分片
      let remainingData = totalDataLength;
      let numFragments = 1; // 至少有一个分片
      
      remainingData -= firstFrameDataSize;
      while (remainingData > 0) {
        remainingData -= middleFrameDataSize;
        numFragments++;
      }
      
      this.logger.log(`总数据长度: ${totalDataLength}字节，需要${numFragments}个分片`);
      
      // 发送所有分片
      let offset = 0;
      let fragmentIndex = 0;
      let result;
      
      while (offset < totalDataLength) {
        const isLastFragment = (fragmentIndex === numFragments - 1);
        const isFirstFragment = (fragmentIndex === 0);
        
        // 确定当前分片的数据大小
        let currentFragmentSize;
        if (isFirstFragment) {
          currentFragmentSize = Math.min(firstFrameDataSize, totalDataLength);
        } else {
          currentFragmentSize = Math.min(middleFrameDataSize, totalDataLength - offset);
        }
        
        // 准备当前分片的数据
        let fragmentData;
        if (!isLastFragment) {
          // 非最后一个分片，需要添加内容总长度
          fragmentData = new Uint8Array(currentFragmentSize + 2);
          // 设置内容总长度（2字节，小端序）
          fragmentData[0] = totalDataLength & 0xFF;
          fragmentData[1] = (totalDataLength >> 8) & 0xFF;
          // 复制数据
          fragmentData.set(data.slice(offset, offset + currentFragmentSize), 2);
        } else {
          // 最后一个分片，直接使用剩余数据
          fragmentData = data.slice(offset);
        }
        
        // 设置帧控制标志
        let frameCtrl = 0;
        if (!isLastFragment) {
          // 非最后一个分片，设置分片标志
          frameCtrl |= FRAME_CTRL_FRAG;
        }
        
        // 构建并发送当前分片
        const frame = this._buildFrameWithCtrl(FRAME_TYPE.DATA, subType, fragmentData, frameCtrl);
        result = await this._writeData(frame);
        
        // 更新偏移量和分片索引
        if (isFirstFragment) {
          offset += firstFrameDataSize;
        } else {
          offset += middleFrameDataSize;
        }
        fragmentIndex++;
        
        // 添加一些延迟，避免发送过快导致接收方处理不过来
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      return result;
    }
  }

  /**
   * 构建帧
   * @private
   */
  _buildFrame(frameType, frameSubType, data, needAck = false, needChecksum = null) {
    // 如果needChecksum为null，则使用全局设置
    if (needChecksum === null) {
      needChecksum = this.enableChecksum;
    }
    
    // 帧控制字段
    let frameControl = 0;
    
    // 设置帧类型和子类型
    const typeSubType = (frameType & 0x03) | ((frameSubType & 0x3F) << 2);
    
    // 设置帧控制位
    if (needChecksum) {
      frameControl |= FRAME_CTRL_CHECKSUM;
    }
    
    if (needAck) {
      frameControl |= FRAME_CTRL_REQUIRE_ACK;
    }
    
    // 暂时禁用加密
    // if (this.isEncrypted && !(frameType === FRAME_TYPE.DATA && frameSubType === DATA_SUBTYPE.NEG_DATA)) {
    //   frameControl |= FRAME_CTRL_ENCRYPTED;
    //   processedData = this._encrypt(data, this.sequence);
    // }
    
    let processedData = data;
    
    // 序列号自增
    this.sequence = (this.sequence + 1) % 256;
    
    // 构建帧: (类型+子类型 共1byte) + 帧控制 + 序列号 + 数据长度 + 数据 + 校验和
    const frameSize = needChecksum ? 4 + processedData.length + 2 : 4 + processedData.length;
    const frame = new Uint8Array(frameSize);
    
    // 填充帧头
    frame[0] = typeSubType;
    frame[1] = frameControl;
    frame[2] = this.sequence;
    frame[3] = processedData.length;
    
    // 复制数据
    if (processedData.length > 0) {
      frame.set(processedData, 4);
    }
    
    // 计算校验和
    if (needChecksum) {
      this.logger.log("frame", frame)
      const checksum = this._calculateChecksum(frame.subarray(2, 4 + processedData.length));
      frame[4 + processedData.length] = checksum & 0xFF;
      frame[4 + processedData.length + 1] = (checksum >> 8) & 0xFF;
      this.logger.log("after frame", checksum, frame)
    }
    
    // 打印组装好的帧（十六进制格式）
    this.logger.log('组装帧:', Array.from(frame).map(b => b.toString(16).padStart(2, '0')).join(' '));
    return frame;
  }
  
  /**
   * 构建带有自定义帧控制的帧
   * @private
   */
  _buildFrameWithCtrl(frameType, frameSubType, data, frameCtrl) {
    // 如果启用校验和，添加校验和标志
    if (this.enableChecksum) {
      frameCtrl |= FRAME_CTRL_CHECKSUM;
    }
    // 增加序列号
    this.sequence = (this.sequence + 1) % 256;
    
    // 计算类型字段
    const type = ((frameSubType & 0x3F) << 2) | (frameType & 0x03);
    
    // 准备数据
    const dataLength = data ? data.length : 0;
    const checksumLength = this.enableChecksum? 2: 0;
    const frameLength = 4 + dataLength + checksumLength; // 类型(1) + 帧控制(1) + 序列号(1) + 数据长度(1) + 数据(n) + 校验和(2)
    
    const frame = new Uint8Array(frameLength);
    frame[0] = type;
    frame[1] = frameCtrl;
    frame[2] = this.sequence;
    frame[3] = dataLength;
    
    if (data && dataLength > 0) {
      frame.set(data, 4);
    }
    
    // 计算校验和
    if(this.enableChecksum){
      const checksum = this._calculateChecksum(frame.subarray(2, 4 + dataLength));
      frame[4 + dataLength] = checksum & 0xFF;
      frame[4 + dataLength + 1] = (checksum >> 8) & 0xFF;
    }
    
    return frame;
  }
  
  /**
   * 计算CRC16校验值
   * @param {Uint8Array} data - 需要计算校验和的数据
   * @param {Number} [length] - 数据长度，如果未提供则使用data.length
   * @param {Number} [iv8] - 序列号，用于校验，
   * @returns {Number} - 16位校验和
   * @private
   */
  _calculateChecksum(data, length, iv8) {
    this.logger.log("calculateChecksum", data, length, iv8);
    // 处理参数缺失情况
    if (length === undefined) {
      length = data.length;
    }
    
    // iv8 参数在 ESP32 的实现中被忽略，这里也忽略
    
    // CRC16-CCITT (BE) 查表法
    const crc16_be_table = [
      0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
      0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
      0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
      0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
      0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823, 0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
      0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
      0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
      0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
      0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
      0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
      0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
      0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
      0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
      0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
      0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
      0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
    ];
    
    // 初始CRC值取反
    let crc = 0xFFFF;
    
    // 计算CRC16
    for (let i = 0; i < length; i++) {
      crc = (crc16_be_table[(crc >> 8) ^ data[i]] ^ (crc << 8)) & 0xFFFF;
    }
    
    // 返回结果取反
    return ~crc & 0xFFFF;
  }

  /**
   * 写入数据
   * @private
   */
  async _writeData(data) {
    // if (!this.connected) {
    //   throw new Error('设备未连接');
    // }
    
    try {
      await this._promisify(wx.writeBLECharacteristicValue, {
        deviceId: this.deviceId,
        serviceId: this.serviceId,
        characteristicId: this.writeCharId,
        value: data.buffer
      });
      
      this.logger.log('数据写入成功:', this._arrayBufferToHex(data.buffer));
      return true;
    } catch (error) {
      this.logger.warn('数据写入失败:', error);
      throw error;
    }
  }

  /**
   * 将微信API转换为Promise
   * @private
   */
  _promisify(fn, params = {}) {
    return new Promise((resolve, reject) => {
      fn({
        ...params,
        success: resolve,
        fail: reject
      });
    });
  }

  /**
   * 字符串转Uint8Array
   * @private
   */
  _stringToUint8Array(str) {
    if (typeof wx !== 'undefined' && wx.utf8Encode) {
      // 使用微信小程序的API（如果可用）
      return new Uint8Array(wx.utf8Encode(str));
    }
    
    // 手动实现UTF-8编码
    let utf8 = [];
    for (let i = 0; i < str.length; i++) {
      let charCode = str.charCodeAt(i);
      
      // 处理代理对（surrogate pairs）
      if (charCode >= 0xD800 && charCode <= 0xDBFF && i + 1 < str.length) {
        const nextCode = str.charCodeAt(i + 1);
        if (nextCode >= 0xDC00 && nextCode <= 0xDFFF) {
          // 计算完整的Unicode代码点
          charCode = ((charCode - 0xD800) << 10) + (nextCode - 0xDC00) + 0x10000;
          i++;
        }
      }
      
      // 根据Unicode代码点值进行UTF-8编码
      if (charCode < 0x80) {
        // 单字节字符 (0-127)
        utf8.push(charCode);
      } else if (charCode < 0x800) {
        // 双字节字符 (128-2047)
        utf8.push(0xC0 | (charCode >> 6), 
                  0x80 | (charCode & 0x3F));
      } else if (charCode < 0x10000) {
        // 三字节字符 (2048-65535)
        utf8.push(0xE0 | (charCode >> 12), 
                  0x80 | ((charCode >> 6) & 0x3F), 
                  0x80 | (charCode & 0x3F));
      } else {
        // 四字节字符 (65536-1114111)
        utf8.push(0xF0 | (charCode >> 18), 
                  0x80 | ((charCode >> 12) & 0x3F), 
                  0x80 | ((charCode >> 6) & 0x3F), 
                  0x80 | (charCode & 0x3F));
      }
    }
    
    return new Uint8Array(utf8);
  }

  static uint8ArrayToString(array) {
    // 手动实现UTF-8解码
    let out = '';
    let i = 0;
    while (i < array.length) {
      let c = array[i++];
      
      // ASCII字符（0-127）
      if (c < 128) {
        out += String.fromCharCode(c);
        continue;
      }
      
      // 处理多字节UTF-8字符
      let char = 0;
      let bytesNeeded = 0;
      let bytesHandled = 0;
      
      // 确定字节数
      if ((c & 0xE0) === 0xC0) { // 2字节字符
        bytesNeeded = 1;
        char = c & 0x1F;
      } else if ((c & 0xF0) === 0xE0) { // 3字节字符
        bytesNeeded = 2;
        char = c & 0x0F;
      } else if ((c & 0xF8) === 0xF0) { // 4字节字符
        bytesNeeded = 3;
        char = c & 0x07;
      } else {
        // 无效的UTF-8字符，跳过
        continue;
      }
      
      // 读取后续字节
      while (bytesHandled < bytesNeeded && i < array.length) {
        c = array[i++];
        if ((c & 0xC0) === 0x80) { // 是UTF-8后续字节
          char = (char << 6) | (c & 0x3F);
          bytesHandled++;
        } else {
          // 无效的UTF-8序列，回退一个字节
          i--;
          break;
        }
      }
      
      // 如果成功读取了所有需要的字节
      if (bytesHandled === bytesNeeded) {
        // 处理代理对
        if (char > 0xFFFF) {
          char -= 0x10000;
          out += String.fromCharCode(0xD800 + (char >> 10));
          char = 0xDC00 + (char & 0x3FF);
        }
        out += String.fromCharCode(char);
      }
    }
    
    return out;
  }

  /**
   * ArrayBuffer转16进制字符串
   * @private
   */
  _arrayBufferToHex(buffer) {
    return Array.prototype.map.call(
      new Uint8Array(buffer),
      x => ('00' + x.toString(16)).slice(-2)
    ).join(' ');
  }
}
module.exports = {
  BluFi,
  WIFI_MODE,
  FRAME_TYPE,
  CTRL_SUBTYPE,
  DATA_SUBTYPE,
  SEC_MODE,
  STATION_CONNECT_STATUS
};
