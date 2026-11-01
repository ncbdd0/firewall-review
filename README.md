# 防火墙复习要塞 🔒

> ## ⚠️ 个人使用 · PERSONAL USE ONLY
> 本仓库及站点仅供仓库所有者**个人学习复习使用**，不对外提供任何服务，请勿 fork、部署或二次分发。

个人复习自测站点：背诵模式 / 做题模式 / 知识库三合一。

## 🔐 访问控制

- 网站地址：<https://ncbdd0.github.io/firewall-review/>
- **需要访问密码**：题库全部内容以 AES-256-CBC 加密存储（PBKDF2 派生密钥，25 万次迭代），打开网站后须输入正确密码方可在浏览器本地解密使用
- 密码与解密过程均不离开浏览器，仓库内**不含任何明文内容**
- 无密码者只能看到锁定页，无法获取题库与知识库内容

## 🧱 技术说明

- 纯原生 HTML / CSS / JavaScript，无后端、无依赖、无追踪
- 加密：OpenSSL AES-256-CBC + PBKDF2-HMAC-SHA256，浏览器端以 Web Crypto API 解密
- 数据：`data/vault.enc`（加密题库与知识库）
- 响应式设计，兼容手机浏览器

## 📁 目录结构

```
├── index.html      # 入口（含密码锁定层）
├── styles.css      # 样式
├── app.js          # 应用逻辑（解密 + 三模式）
└── data/vault.enc  # 加密数据（无密码不可读）
```

---

© 个人使用 · Personal use only
