# ESP32 BluFi 配网 - H5版本

这是ESP32 BluFi配网功能的Chrome浏览器版本示例。

## 功能特性

- ✅ 支持Chrome浏览器的Web Bluetooth API
- ✅ 设备扫描和连接
- ✅ WiFi网络扫描和配置
- ✅ 自定义数据发送和接收
- ✅ 实时日志显示
- ✅ 本地设置存储
- ✅ 响应式设计，支持移动设备

## 浏览器要求

- Chrome 56+ 或 Edge 79+ 等支持Web Bluetooth API的浏览器
- 需要HTTPS环境（本地开发可使用localhost）
- 需要用户手动启用蓝牙权限

## 使用方法

1. 在支持Web Bluetooth的浏览器中打开 `index.html`
2. 配置BluFi设置（设备前缀、超时时间、校验选项）
3. 点击"初始化BluFi"按钮
4. 点击"扫描设备"按钮，选择要连接的ESP32设备
5. 连接成功后，扫描并选择WiFi网络
6. 输入WiFi密码并配置

## 注意事项

- Web Bluetooth API需要用户交互才能启动设备扫描
- 某些功能可能需要用户手动授权蓝牙权限
- 建议在HTTPS环境下使用以确保最佳兼容性

## 文件说明

- `index.html` - 主页面文件
- `style.css` - 样式文件
- `app.js` - 应用逻辑文件
- `../src/blufi.js` - BluFi核心库（已适配浏览器环境）

## 开发说明

如需本地开发，建议使用简单的HTTP服务器：

```bash
# 使用Python
python -m http.server 8000

# 使用Node.js
npx http-server

# 使用PHP
php -S localhost:8000
```

然后访问 `http://localhost:8000/h5-example/`