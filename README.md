<div align="center">
  
<img style="width:60px" src="https://raw.githubusercontent.com/link9596/FlyPaste/refs/heads/main/public/favicon.png" alt=""><h1>FlyPaste</h1>

**部署在 Cloudflare 边缘的自托管、端到端加密剪贴板。**

在不同设备间实时同步文本与文件。一个密码即可解锁属于你的加密空间。

简体中文 · [English](./README-en.md) 

[![GitHub license](https://img.shields.io/github/license/link9596/FlyPaste)](https://github.com/link9596/FlyPaste/blob/main/LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)


[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/link9596/FlyPaste)

[**⌨️ 快速开始**](#快速开始) · [**☁️ 在线预览**](https://r2-file.lkin.cn/web/demo/FlyPaste-demo.html) · [**💬 反馈**](https://github.com/link9596/FlyPaste/issues) · [**🛡️ 安全**](#安全说明)

</div>

---

## ✨ 特点

- **设计即端到端加密** — 文本消息在浏览器内先以 AES-256-GCM 加密再上传；密钥由密码经 PBKDF2（31 万次迭代）派生，不离开设备，服务端只存加密后文本。
- **实时同步** — 借助 Cloudflare Durable Objects 用 WebSocket 广播变更，多台设备实时同步。
- **多租户隔离** — 通过 ACCESS_TOKENS 将多个密码映射为相互隔离的租户，实现输入不同密码进入不同的隔离环境。
- **完全免费** — 仅依赖 Workers + R2 + Durable Objects，利用免费额度部署，全球就近分发、极低延迟。

---

## 🚀 核心功能

**文本与文件粘贴板**

- 多会话面板。
- 文本一键复制；支持拖拽、粘贴或选择文件上传和下载。
- 支持 **R2 大文件分片上传**（8 MiB 分片）；文件支持 **自定义过期时间**（最长永久保留）。
- 每个会话自动保留最新 **300 条**消息，超出后从最旧开始裁剪（文件一并清理）。

**同步与会话**

- WebSocket 推送 + 轮询兜底，多设备实时保持一致。
- 7 天滑动续期会话，HttpOnly / Secure / SameSite=Strict Cookie，支持「退出所有设备」。

**安全加固**

- 基于 IP 的登录限流与指数退避，防止暴力破解密码（连续失败 5 次锁定 1 分钟，最高 30 分钟）。
- 恒定时间密码比对；严格 CSP、`X-Frame-Options: DENY`、nosniff 与 `Permissions-Policy` 响应头。
- 每 6 小时定时任务清扫过期会话、文件与限流记录。

**PWA**

- 可安装为网页应用

---

## 🧱 技术栈

| 层次 | 技术 |
| --- | --- |
| 运行时 | Cloudflare Workers |
| 存储 | Cloudflare R2 |
| 实时同步 | Durable Object `SyncHub` |
| 前端 | 原生 HTML, PWA |

---

## 快速开始

1. **一键部署**：点击上方 Deploy to Cloudflare 按钮，按流程完成部署。
2. **配置密钥**：设置环境变量——单个 `ACCESS_TOKEN`（共享一个空间），或 `ACCESS_TOKENS`（JSON 格式的 `密码 → 租户` 映射，用于多隔离空间）。
> 比如环境变量名称`ACCESS_TOKEN`，值为`{"密码123":"用户id"}` 或者多密码形式：`{"密码123":"用户id","password2":"username2"}`
4. **访问并解锁**：访问 Worker 域名，输入密码——它既用于身份认证，也用于派生加密密钥。
5. **开始粘贴**：创建会话，粘贴文本或拖入文件；其他设备会实时看到变化。

⚠️⚠️ 建议使用HTTPS访问，否则可能会导致登陆失败

建议在`SSL/TLS` > `边缘证书` 里开启 始终使用HTTPS。

---

## 安全说明

- 文本消息端到端加密；**文件不进行加密**——请保持部署私密，敏感材料建议设置过期时间。
- 密码即主密钥：丢失密码意味着文本数据无法解密。

## 许可证

GPL-3.0 license
