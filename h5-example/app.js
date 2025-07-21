// H5版本的BluFi配网应用
class BluFiApp {
    constructor() {
        this.blufi = null;
        this.connected = false;
        this.bluetoothReady = false;
        this.blufiInitialized = false;
        this.devices = [];
        this.wifiList = [];
        this.selectedSsid = '';
        this.showPassword = false;
        this.isShowLog = false;
        this.log = [];
        this.receivedCustomData = [];
        
        this.initElements();
        this.bindEvents();
        this.loadSettings();
    }

    // 初始化DOM元素引用
    initElements() {
        this.elements = {
            // 设置相关
            prefix: document.getElementById('prefix'),
            scanWifiTimeout: document.getElementById('scanWifiTimeout'),
            enableChecksum: document.getElementById('enableChecksum'),
            initBluFi: document.getElementById('initBluFi'),
            
            // 设备连接相关
            scanDevices: document.getElementById('scanDevices'),
            disconnectDevice: document.getElementById('disconnectDevice'),
            deviceList: document.getElementById('deviceList'),
            devices: document.getElementById('devices'),
            
            // WiFi配置相关
            wifiSection: document.getElementById('wifiSection'),
            scanWifi: document.getElementById('scanWifi'),
            wifiList: document.getElementById('wifiList'),
            wifiNetworks: document.getElementById('wifiNetworks'),
            wifiForm: document.getElementById('wifiForm'),
            ssid: document.getElementById('ssid'),
            password: document.getElementById('password'),
            showWifiList: document.getElementById('showWifiList'),
            togglePassword: document.getElementById('togglePassword'),
            
            // 自定义数据相关
            customDataForm: document.getElementById('customDataForm'),
            customData: document.getElementById('customData'),
            receivedData: document.getElementById('receivedData'),
            
            // 状态和日志相关
            statusText: document.getElementById('statusText'),
            showLog: document.getElementById('showLog'),
            logWindow: document.getElementById('logWindow'),
            closeLog: document.getElementById('closeLog'),
            logContent: document.getElementById('logContent')
        };
    }

    // 绑定事件监听器
    bindEvents() {
        // 设置相关事件
        this.elements.prefix.addEventListener('input', () => this.saveSettings());
        this.elements.scanWifiTimeout.addEventListener('input', () => this.saveSettings());
        this.elements.enableChecksum.addEventListener('change', () => this.saveSettings());
        this.elements.initBluFi.addEventListener('click', () => this.initBluFi());
        
        // 设备连接相关事件
        this.elements.scanDevices.addEventListener('click', () => this.scanDevices());
        this.elements.disconnectDevice.addEventListener('click', () => this.disconnectDevice());
        
        // WiFi配置相关事件
        this.elements.scanWifi.addEventListener('click', () => this.scanWifi());
        this.elements.showWifiList.addEventListener('click', () => this.toggleWifiList());
        this.elements.togglePassword.addEventListener('click', () => this.togglePasswordVisibility());
        this.elements.wifiForm.addEventListener('submit', (e) => this.configureWifi(e));
        
        // 自定义数据相关事件
        this.elements.customDataForm.addEventListener('submit', (e) => this.sendCustomData(e));
        
        // 日志相关事件
        this.elements.showLog.addEventListener('click', () => this.showLog());
        this.elements.closeLog.addEventListener('click', () => this.hideLog());
    }

    // 加载本地存储的设置
    loadSettings() {
        const prefix = localStorage.getItem('blufi_prefix');
        const scanWifiTimeout = localStorage.getItem('blufi_scanWifiTimeout');
        const enableChecksum = localStorage.getItem('blufi_enableChecksum');
        
        if (prefix) {
            this.elements.prefix.value = prefix;
        }
        if (scanWifiTimeout) {
            this.elements.scanWifiTimeout.value = scanWifiTimeout;
        }
        if (enableChecksum !== null) {
            this.elements.enableChecksum.checked = enableChecksum === 'true';
        }
    }

    // 保存设置到本地存储
    saveSettings() {
        localStorage.setItem('blufi_prefix', this.elements.prefix.value);
        localStorage.setItem('blufi_scanWifiTimeout', this.elements.scanWifiTimeout.value);
        localStorage.setItem('blufi_enableChecksum', this.elements.enableChecksum.checked);
    }

    // 初始化BluFi
    async initBluFi() {
        try {
            // 检查浏览器是否支持Web Bluetooth
            if (!navigator.bluetooth) {
                throw new Error('此浏览器不支持Web Bluetooth API。请使用Chrome 56+或Edge 79+等支持的浏览器。');
            }

            const prefix = this.elements.prefix.value || 'BLUFI_DEVICE';
            const scanWifiTimeout = parseInt(this.elements.scanWifiTimeout.value) || 10000;
            const enableChecksum = this.elements.enableChecksum.checked;

            this.blufi = new BluFi({
                devicePrefix: prefix,
                scanWifiTimeout: scanWifiTimeout,
                enableChecksum: enableChecksum,
                onCustomData: (data) => this.onCustomDataReceived(data),
                logger: {
                    log: (...args) => this.addLog('log', args.join(' ')),
                    warn: (...args) => this.addLog('warn', args.join(' '))
                }
            });

            await this.blufi.init();
            this.bluetoothReady = true;
            this.blufiInitialized = true;
            
            this.addLog('log', 'BluFi初始化成功');
            this.updateUI();
        } catch (error) {
            this.addLog('warn', `BluFi初始化失败: ${error.message}`);
            alert(`初始化失败: ${error.message}`);
        }
    }

    // 扫描设备
    async scanDevices() {
        try {
            this.addLog('log', '开始扫描设备...');
            this.devices = await this.blufi.scanDevices();
            this.addLog('log', `扫描到 ${this.devices.length} 个设备`);
            this.renderDevices();
        } catch (error) {
            this.addLog('warn', `扫描设备失败: ${error.message}`);
            alert(`扫描失败: ${error.message}`);
        }
    }

    // 连接设备
    async connectDevice(deviceId) {
        try {
            this.addLog('log', `正在连接设备: ${deviceId}`);
            await this.blufi.connect(deviceId);
            this.connected = true;
            this.addLog('log', '设备连接成功');
            this.updateUI();
        } catch (error) {
            this.addLog('warn', `连接设备失败: ${error.message}`);
            alert(`连接失败: ${error.message}`);
        }
    }

    // 断开设备连接
    async disconnectDevice() {
        try {
            await this.blufi.disconnect();
            this.connected = false;
            this.wifiList = [];
            this.selectedSsid = '';
            this.elements.ssid.value = '';
            this.addLog('log', '设备已断开连接');
            this.updateUI();
        } catch (error) {
            this.addLog('warn', `断开连接失败: ${error.message}`);
        }
    }

    // 扫描WiFi
    async scanWifi() {
        try {
            this.addLog('log', '开始扫描WiFi...');
            this.wifiList = await this.blufi.scanWifi();
            this.addLog('log', `扫描到 ${this.wifiList.length} 个WiFi网络`);
            this.renderWifiList();
        } catch (error) {
            this.addLog('warn', `扫描WiFi失败: ${error.message}`);
            alert(`WiFi扫描失败: ${error.message}`);
        }
    }

    // 选择WiFi
    selectWifi(ssid) {
        this.selectedSsid = ssid;
        this.elements.ssid.value = ssid;
        this.elements.wifiList.style.display = 'none';
        this.addLog('log', `已选择WiFi: ${ssid}`);
    }

    // 配置WiFi
    async configureWifi(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const ssid = formData.get('ssid') || this.elements.ssid.value;
        const password = formData.get('password') || this.elements.password.value;

        if (!ssid) {
            alert('请选择WiFi网络');
            return;
        }

        try {
            this.addLog('log', `正在配置WiFi: ${ssid}`);
            await this.blufi.configureWifi({
                ssid: ssid,
                password: password
            });
            this.addLog('log', 'WiFi配置成功');
            alert('WiFi配置成功！');
        } catch (error) {
            this.addLog('warn', `WiFi配置失败: ${error.message}`);
            alert(`WiFi配置失败: ${error.message}`);
        }
    }

    // 处理接收到的自定义数据
    onCustomDataReceived(data) {
        try {
            // 将Uint8Array转换为字符串
            const receivedStr = new TextDecoder().decode(data);
            this.addLog('log', `接收到自定义数据: ${receivedStr}`);
            
            // 在页面上显示接收到的数据
            this.receivedCustomData = receivedStr;
            this.updateReceivedDataDisplay();
        } catch (error) {
            this.addLog('warn', `处理接收数据失败: ${error.message}`);
        }
    }

    // 更新页面上接收数据的显示
    updateReceivedDataDisplay() {
        const receivedDataElement = document.getElementById('receivedCustomData');
        if (receivedDataElement) {
            receivedDataElement.textContent = this.receivedCustomData || '暂无数据';
        }
    }

    // 发送自定义数据
    async sendCustomData(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const customData = formData.get('customData') || this.elements.customData.value;

        if (!customData) {
            alert('请输入要发送的数据');
            return;
        }

        try {
            this.addLog('log', `发送自定义数据: ${customData}`);
            // 使用sendCustomStr方法发送字符串数据
            await this.blufi.sendCustomStr(customData);
            this.addLog('log', '自定义数据发送成功');
            this.elements.customData.value = '';
        } catch (error) {
            this.addLog('warn', `发送自定义数据失败: ${error.message}`);
            alert(`发送失败: ${error.message}`);
        }
    }

    // 切换密码显示/隐藏
    togglePasswordVisibility() {
        this.showPassword = !this.showPassword;
        this.elements.password.type = this.showPassword ? 'text' : 'password';
        this.elements.togglePassword.textContent = this.showPassword ? '隐藏' : '显示';
    }

    // 切换WiFi列表显示/隐藏
    toggleWifiList() {
        const isVisible = this.elements.wifiList.style.display !== 'none';
        this.elements.wifiList.style.display = isVisible ? 'none' : 'block';
    }

    // 显示日志
    showLog() {
        this.isShowLog = true;
        this.elements.logWindow.style.display = 'block';
        this.renderLog();
    }

    // 隐藏日志
    hideLog() {
        this.isShowLog = false;
        this.elements.logWindow.style.display = 'none';
    }

    // 添加日志
    addLog(type, message) {
        const now = new Date();
        const time = now.toLocaleTimeString();
        this.log.unshift({
            type: type,
            time: time,
            data: message
        });
        
        // 限制日志数量
        if (this.log.length > 100) {
            this.log = this.log.slice(0, 100);
        }
        
        if (this.isShowLog) {
            this.renderLog();
        }
    }

    // 渲染设备列表
    renderDevices() {
        if (this.devices.length === 0) {
            this.elements.deviceList.style.display = 'none';
            return;
        }

        this.elements.deviceList.style.display = 'block';
        this.elements.devices.innerHTML = '';

        this.devices.forEach(device => {
            const deviceElement = document.createElement('div');
            deviceElement.className = 'device-item';
            deviceElement.innerHTML = `
                <div class="device-name">${device.name || '未命名设备'}</div>
                <div class="device-id">ID: ${device.deviceId}</div>
                <div class="device-rssi">信号强度: ${device.RSSI || 'N/A'} dBm</div>
            `;
            deviceElement.addEventListener('click', () => this.connectDevice(device.deviceId || device));
            this.elements.devices.appendChild(deviceElement);
        });
    }

    // 渲染WiFi列表
    renderWifiList() {
        if (this.wifiList.length === 0) {
            this.elements.wifiList.style.display = 'none';
            return;
        }

        this.elements.wifiNetworks.innerHTML = '';

        this.wifiList.forEach(wifi => {
            const wifiElement = document.createElement('div');
            wifiElement.className = 'wifi-item';
            wifiElement.innerHTML = `
                <div class="wifi-name">${wifi.ssid}</div>
                <div class="wifi-rssi">信号强度: ${wifi.rssi}</div>
            `;
            wifiElement.addEventListener('click', () => this.selectWifi(wifi.ssid));
            this.elements.wifiNetworks.appendChild(wifiElement);
        });
    }

    // 渲染日志
    renderLog() {
        this.elements.logContent.innerHTML = '';
        
        this.log.forEach(logItem => {
            const logElement = document.createElement('div');
            logElement.className = logItem.type;
            logElement.textContent = `${logItem.time} [${logItem.type}] ${logItem.data}`;
            this.elements.logContent.appendChild(logElement);
        });
    }

    // 更新UI状态
    updateUI() {
        // 更新按钮状态
        this.elements.initBluFi.disabled = this.blufiInitialized;
        this.elements.scanDevices.disabled = !this.bluetoothReady || this.connected || !this.blufiInitialized;
        this.elements.disconnectDevice.disabled = !this.connected;

        // 更新设备列表显示
        if (this.connected) {
            this.elements.deviceList.style.display = 'none';
        }

        // 更新WiFi配置区域显示
        this.elements.wifiSection.style.display = this.connected ? 'block' : 'none';

        // 更新状态文本
        this.elements.statusText.textContent = this.connected ? '已连接' : '未连接';
    }
}

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
    window.blufiApp = new BluFiApp();
});