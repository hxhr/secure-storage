# 🔐 Secure Storage

一个基于 Flask + AES 加密的安全文件存储系统，支持高效文件上传、分块加密、共享、下载与删除操作。使用客户端和服务器分离设计，适合教学项目与安全应用的基础实现。

## ✨ 功能特性

- ✅ 用户注册与登录
- ✅ AES 对称加密存储文件
- ✅ 分块上传与下载，支持局部更新
- ✅ 文件哈希校验，确保完整性
- ✅ 文件共享功能
- ✅ 权限控制：用户只能访问自己的文件或被共享的文件
- ✅ 本地存储 hashmap 映射
- ✅ 文件删除、密码修改等实用操作

## 🖼️ 系统结构

- `client_main.py`：命令行客户端入口
- `client_functions.py`：用户认证与密钥管理
- `clientfile_handler.py`：上传、下载、共享、删除等核心功能
- `server.py`：Flask 后端服务，处理各类 API 请求
- `secure_storage.db`：SQLite 数据库存储用户和文件信息
- `hashmap/`：本地 hashmap 缓存目录



