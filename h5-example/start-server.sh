#!/bin/bash
echo "启动ESP32 BluFi配网H5示例服务器..."
echo ""
echo "请确保您使用的是支持Web Bluetooth API的浏览器（Chrome 56+或Edge 79+）"
echo ""
echo "服务器启动后，请在浏览器中访问："
echo "http://localhost:8000/h5-example/"
echo ""
echo "按Ctrl+C停止服务器"
echo ""
python3 -m http.server 8000