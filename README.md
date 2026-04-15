# Secure Hub IAM Demo

一个用于演示多主体认证、OTP MFA、Passkey、受信设备与多设备会话管理的 Demo。

## 支持的主体

- `member`
- `community_staff`
- `platform_staff`

## 支持的认证方式

- Password
- OTP
- Passkey

> 当前版本中，MFA 统一使用 **OTP**。

---

## 演示视频

仓库根目录中的：

- `演示.mp4`

是本项目的演示视频。

---

## 使用方式

### 1. 使用 Docker 启动

在项目根目录执行：

```powershell
docker compose up -d --build
```

启动后访问：

- Frontend: `http://localhost:13000`
- API: `http://localhost:18082`
- Health Check: `http://localhost:18082/health`

查看容器状态：

```powershell
docker compose ps
```

查看日志：

```powershell
docker compose logs api --tail 200
docker compose logs web --tail 200
```

---

### 2. 登录入口

- `http://localhost:13000/auth/member`
- `http://localhost:13000/auth/community`
- `http://localhost:13000/auth/platform`

---

### 3. 演示账号

#### Member / Community

- Email: `alex@example.com`
- Password: `Passw0rd!`

#### Platform

- Email: `platform@example.com`
- Password: `Platf0rm!`

---

### 4. OTP 使用说明

开发环境下：

- 后端会返回 `demo_code`
- 前端页面也会直接显示 OTP

所以本地演示时可直接使用页面展示的验证码。

---

### 5. Passkey 使用说明

请务必使用：

```text
http://localhost:13000
```

不要使用：

```text
http://127.0.0.1:13000
```

否则浏览器可能报：

```text
127.0.0.1 is an invalid domain
```

#### 注册 Passkey

1. 打开 `http://localhost:13000`
2. 使用 Password 或 OTP 登录
3. 如果需要，先完成 OTP MFA
4. 进入 Dashboard
5. 点击“注册 Passkey”

#### 使用 Passkey 登录

前提是该主体已经注册过 Passkey。

---

## Dashboard 功能

登录后会进入对应主体的 Dashboard：

- `/dashboard/member`
- `/dashboard/community`
- `/dashboard/platform`

可进行：

- 查看活跃会话
- 注册 Passkey
- 下线指定设备
- 下线其他设备
- 退出登录

---

## API 文档

- OpenAPI: [`openapi/openapi.yaml`](./openapi/openapi.yaml)
- Postman: [`postman/IAM.postman_collection.json`](./postman/IAM.postman_collection.json)

---

## 测试

### 后端测试

```powershell
docker compose run --rm api-test
```

### 前端构建检查

```powershell
cd apps/web
npm install
npm run build
```

