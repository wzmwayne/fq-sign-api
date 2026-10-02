# 番茄小说签名 API（fq-sign-api）

一个**自托管的番茄小说签名服务**：`POST` 一个 URL，返回该请求所需的**全部 8 个签名头**。

```
X-Khronos   X-Neptune   X-Soter    X-Ladon
X-Argus     X-Helios    X-Gorgon   X-Medusa
```

> ## ⚠️ 合规提示（务必先读）
> - 本项目**仅供学习与安全研究**：Android 原生库加载、JNI 环境模拟、请求签名机制分析。
> - 本仓库**不包含任何官方二进制文件**（`libmetasec_ml.so` / `libc++_shared.so` / APK / 证书等），
>   **需要使用者自行提供**（见下方"准备工作"）。请只从**你自己合法持有的 App** 中提取。
> - 请遵守你所在地区的法律法规与目标服务的使用条款。
>   **请勿用于商业用途、批量抓取、绕过付费或其他侵权场景。**
> - 使用本项目产生的一切后果由使用者自行承担。

---

## 工作原理

用 [unidbg](https://github.com/zhkl0228/unidbg) 在 JVM 内构造一套 Android 运行环境
（bionic libc、JNI、文件系统、属性区），加载官方的 `libmetasec_ml.so`，
调用其签名入口 `base + 0x168c80(url, header)`，拿到 8 个签名头。
**不需要真机、不需要 Root、不需要模拟器**（unidbg 是纯 Java 的指令级模拟）。

## 功能特性

- `POST /sign` → JSON 返回 8 个签名头（也可返回原始多行文本）
- **完全串行**处理（匹配签名器真实能力，避免"假并行"）
- **有界排队**：最多排队 20 个，超出**立即**返回 503（实测 0.11–0.17s，不是等超时）
- **单 IP 限速** 1 次 / 5 秒 → 429 + `Retry-After`
- **防伪造 IP 头**：取**所有**候选来源（`CF-Connecting-IP` / `True-Client-IP` / `X-Real-IP` /
  `X-Forwarded-For` 全部跳 / `CF-Pseudo-IPv4` / socket 对端），**任一个超限即拒绝**
- `/health` 监控端点（`inflight` / `served` / `rejected`）
- 容器化部署（`deploy/` 下有 Dockerfile 与 compose）

## 准备工作：把官方库放到「服务端同目录的 data/」

本仓库**不包含**官方二进制，需要你自己准备。**推荐放在服务端同目录的 `data/` 下**（这样它不会被打进 jar / 镜像）：

```
data/                          ← 与环境变量 FQ_DATA_DIR 同级即可
├── libmetasec_ml.so           # 必需
├── libc++_shared.so           # 必需（arm64-v8a）
├── base.apk                   # 占位即可（纯签名服务不需要真 APK，可放空文件）
└── ms_16777218.bin            # 可选（运行时生成的证书文件，缺失时部分流程可能失败）
```

**一键提取**（从你自己合法持有的 APK）：

```bash
./scripts/fetch-data.sh /path/to/你的番茄小说.apk
```

**目录查找顺序**（代码实现，见 `IdleFQ.dataDir()`）：

1. 环境变量 `FQ_DATA_DIR` 指定的目录
2. **jar 同级的 `data/`** ← 推荐
3. 当前工作目录的 `data/`
4. 都找不到 ⇒ 回退到 jar 内打包的资源

> 也可用 `FQ_DATA_DIR=/somewhere/else` 指定任意位置。

## 快速开始

### 方式一：Docker（推荐）

```bash
# 1) 构建 jar（需要 JDK 21）
cd server && gradle jar          # 产物：build/libs/fq_download.jar

# 2) 部署
cd ../deploy
mkdir -p app && cp ../../server/build/libs/fq_download.jar app/
docker compose up -d --build

# 3) 验证
curl -s http://127.0.0.1:18090/health
```

### 方式二：直接运行

```bash
cd server
gradle jar
java -jar build/libs/fq_download.jar serve 8090      # 常驻服务
java -jar build/libs/fq_download.jar sign  "https://..."   # 单次签名
```

## API

### `POST /sign`

请求体可以直接是 URL，也可以是 JSON：

```bash
curl -X POST -d 'https://api5-normal-sinfonlineb.fqnovel.com/reading/reader/batch_full/v1?...' \
     http://127.0.0.1:18090/sign
```
```bash
curl -X POST -H 'Content-Type: application/json' \
     -d '{"url":"https://...","header":"可选的自定义头"}' \
     http://127.0.0.1:18090/sign
```

响应：

```json
{
  "ok": true,
  "headers": {
    "X-Argus": "…", "X-Gorgon": "…", "X-Helios": "…", "X-Khronos": "…",
    "X-Ladon": "…", "X-Medusa": "…", "X-Neptune": "…", "X-Soter": "…"
  }
}
```

| 状态码 | 含义 | 响应 |
|---|---|---|
| 200 | 成功 | `{"ok":true,"headers":{…}}` |
| 400 | 缺 url | `{"ok":false,"error":"missing url"}` |
| 429 | 触发单 IP 限速 | `{"ok":false,"error":"rate limited","retry_after":N,"ip":"…"}` + `Retry-After` |
| 503 | 队列已满（立即返回） | `{"ok":false,"error":"server overloaded","queue":20}` |
| 500 | 内部错误 | `{"ok":false,"error":"internal"}` |

### `GET /health`

```json
{"status":"ok","inflight":0,"served":22,"rejected":10}
```

## 可调参数（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `FQ_MAX_QUEUE` | `20` | 最多排队多少个请求（超出立即 503） |
| `FQ_PER_IP_MS` | `5000` | 单 IP 最小间隔（毫秒） |

## 性能与资源（实测）

| 指标 | 数值 |
|---|---|
| 单次签名（常驻热态） | **≈ 0.4 s** |
| 单次签名（每次 `java -jar` 冷启动） | 2.8 – 7 s |
| 内存（调优参数） | **≈ 113–126 MB** |
| 内存（JVM 默认参数） | ≈ 155 MB |
| 吞吐 | 串行，≈ 2.5 次/秒（热态） |

## 目录结构

```
server/    Java 服务源码（签名 + API）
deploy/    Dockerfile / compose.yaml / entrypoint.sh（compose 里已挂载 ./data）
python/    纯 Python 参考实现（无需 JVM）
scripts/   fetch-data.sh —— 从你自己的 APK 提取所需原生库到 ./data/
data/      ← 你自己放官方库的地方（不进仓库）
```

## 纯 Python 参考实现（`python/`）

不依赖 unidbg，直接以算法复刻部分头，可用于**交叉校验**服务端返回值的正确性：

| 文件 | 内容 |
|---|---|
| `fq_headers.py` | `X-Khronos` / `X-Neptune` / `X-Soter` / `X-Ladon` 的纯 Python 实现 |
| `fq_ladon.py` | `X-Ladon` 独立实现（可 `python3 fq_ladon.py verify` 对比真值） |
| `fq_crypto.py` | 正文解密链路（AES-128-CBC/CTR + PKCS5 + GZIP + Base64） |
| `fq_aes_variant.py` | 该库自有的 AES 变体（线性 T 轮 + 标准密钥编排） |
| `sidecar.py` | 把上述服务包成 HTTP `/sign` 的极简 sidecar（仅标准库） |

> 校验思路：服务端返回的 `X-Ladon` 必须等于本地按同一 `X-Khronos` 算出的值，
> 不等即说明模拟环境异常，可作为**正确性守门员**。

## 常见问题

**Q: 为什么必须自己提供 `.so`？**
A: 它是官方版权物，不能随仓库分发；且不同 App 版本对应的库可能不同。

**Q: 支持并发吗？**
A: 默认**串行 + 排队**。签名库实例本身的状态机并非线程安全，串行是最稳的做法。
若要提高吞吐，可水平扩展多个容器（注意每个实例约 120 MB 内存）。

**Q: 放在公网安全吗？**
A: 请务必加一层鉴权（如 Cloudflare Access + Service Token、API Key、
或只在内网/Tailscale 里暴露）。内置限流只能防滥用，防不住"白嫖"。

## 致谢

- [unidbg](https://github.com/zhkl0228/unidbg) —— 纯 Java 的 Android 原生库模拟框架，本项目的基石

## License

[MIT](LICENSE)
