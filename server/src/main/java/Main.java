import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.anjia.unidbgserver.unidbg.IdleFQ;
import com.anjia.unidbgserver.service.FqCrypto;
import com.anjia.unidbgserver.dto.FqVariable;

public class Main {

    static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    static final String FQ_BASE_URL = "https://api5-normal-sinfonlineb.fqnovel.com";
    static final String FQ_UA_BASE = "com.dragon.read.oversea.gp/68132 (Linux; U; Android 10; zh_CN; OnePlus11; Build/V291IR;tt-ok/3.12.13.4-tiktok)";
    static String FQ_UA = FQ_UA_BASE;
    static String FQ_COOKIE = "store-region=cn-zj; store-region-src=did; install_id=1571665370176443";
    static IdleFQ idleFQ;

    // ================= /sign 服务：准入控制状态 =================
    // 单 IP 最近一次【被接纳】的时间戳（毫秒）。只在请求被接纳时写入，
    // 这样被 429/503 拒掉的请求不会把该 IP 的窗口顶住。
    static final java.util.concurrent.ConcurrentHashMap<String, Long> IP_LAST =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** JSON 字符串转义（签名是多行文本，必须转义换行） */
    static String jesc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.toString();
    }

    /** 统一的 JSON 响应；extraHeaderRetry 非空时追加 Retry-After */
    static void jresp(com.sun.net.httpserver.HttpExchange ex, int code, String json, String retryAfter) {
        try {
            byte[] out = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (retryAfter != null) ex.getResponseHeaders().add("Retry-After", retryAfter);
            ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
            ex.sendResponseHeaders(code, out.length);
            try (java.io.OutputStream os = ex.getResponseBody()) { os.write(out); }
        } catch (Throwable ig) { /* 客户端可能已断开 */ }
    }

    // ==================== 内置 API 文档（Markdown → HTML）====================
    static final String API_DOC_MD = """
# 番茄小说签名 API

`POST /sign` —— 提交一个请求 URL，返回该请求所需的**全部 8 个签名头**：

`X-Khronos` `X-Neptune` `X-Soter` `X-Ladon` `X-Argus` `X-Helios` `X-Gorgon` `X-Medusa`

## 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/sign` | 签名，返回 8 个头 |
| `GET` | `/health` | 运行状态与计数 |
| `GET` | `/` | 本页文档 |

## POST /sign

请求体可以直接是 URL：

```bash
curl -X POST -d 'https://api5-normal-sinfonlineb.fqnovel.com/reading/crypt/registerkey?aid=1967' \\
     http://127.0.0.1:18090/sign
```

也可以是 JSON（`header` 为可选的自定义头）：

```bash
curl -X POST -H 'Content-Type: application/json' \\
     -d '{"url":"https://...","header":""}' http://127.0.0.1:18090/sign
```

成功响应：

```json
{"ok":true,"headers":{"X-Argus":"...","X-Gorgon":"...","X-Helios":"...","X-Khronos":"...","X-Ladon":"...","X-Medusa":"...","X-Neptune":"...","X-Soter":"..."}}
```

## 状态码

| 状态码 | 含义 | 响应 |
|---|---|---|
| `200` | 成功 | `{"ok":true,"headers":{...}}` |
| `400` | 缺少 url | `{"ok":false,"error":"missing url"}` |
| `429` | 单 IP 触发限速 | `{"ok":false,"error":"rate limited","retry_after":N}` + `Retry-After` 头 |
| `503` | 队列已满（**立即**返回） | `{"ok":false,"error":"server overloaded","queue":20}` |
| `500` | 内部错误 | `{"ok":false,"error":"internal"}` |

## 限流与排队

- **完全串行**：同一时刻只处理 1 个签名请求（匹配签名库的真实能力）
- **有界排队**：最多排队 20 个，超出**立即**返回 `503`（实测 0.11~0.17s，不是等超时）
- **单 IP 限速**：1 次 / 5 秒，触发返回 `429` + `Retry-After`
- **防伪造 IP 头**：取**所有**候选来源（`CF-Connecting-IP`、`True-Client-IP`、`X-Real-IP`、
  `X-Forwarded-For` 的每一跳、socket 对端），**任一个超限即拒绝**

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `FQ_MAX_QUEUE` | `20` | 排队上限 |
| `FQ_PER_IP_MS` | `5000` | 单 IP 最小间隔（毫秒） |

## GET /health

```json
{"status":"ok","inflight":0,"served":22,"rejected":10}
```

---

仅供学习与安全研究使用；请遵守当地法律法规与目标服务条款。
""";

    static String htmlEsc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String mdInline(String s) {
        s = htmlEsc(s);
        s = s.replaceAll("`([^`]+)`", "<code>$1</code>");
        s = s.replaceAll("\\*\\*([^*]+)\\*\\*", "<strong>$1</strong>");
        s = s.replaceAll("\\[([^]]+)]\\(([^)]+)\\)", "<a href=\"$2\" target=\"_blank\" rel=\"noopener\">$1</a>");
        return s;
    }

    static void mdFlush(StringBuilder o, java.util.List<String> para) {
        if (para.isEmpty()) return;
        StringBuilder p = new StringBuilder();
        for (String s : para) { if (p.length() > 0) p.append(' '); p.append(s.trim()); }
        o.append("<p>").append(mdInline(p.toString())).append("</p>\n");
        para.clear();
    }

    /** 极简 Markdown 渲染：标题 / 代码块 / 表格 / 列表 / 引用 / 分割线 / 行内样式 */
    static String mdToHtml(String md) {
        StringBuilder o = new StringBuilder();
        String[] ls = md.split("\n", -1);
        boolean inCode = false;
        StringBuilder code = new StringBuilder();
        java.util.List<String> para = new java.util.ArrayList<>();
        for (int i = 0; i < ls.length; i++) {
            String l = ls[i];
            if (l.startsWith("```")) {
                if (!inCode) { inCode = true; code.setLength(0); }
                else { inCode = false; o.append("<pre><code>").append(htmlEsc(code.toString())).append("</code></pre>\n"); }
                continue;
            }
            if (inCode) { code.append(l).append('\n'); continue; }
            if (l.isBlank()) { mdFlush(o, para); continue; }
            if (l.startsWith("|")) {                                  // 表格
                java.util.List<String> rows = new java.util.ArrayList<>();
                int j = i;
                while (j < ls.length && ls[j].startsWith("|")) { rows.add(ls[j]); j++; }
                boolean hasHead = rows.size() > 1 && rows.get(1).matches("^\\|[\\s:\\-|]+\\|\\s*$");
                o.append("<table>\n");
                for (int r = 0; r < rows.size(); r++) {
                    String row = rows.get(r);
                    if (row.matches("^\\|[\\s:\\-|]+\\|\\s*$")) continue;
                    o.append("<tr>");
                    for (String c : row.replaceAll("^\\|", "").replaceAll("\\|\\s*$", "").split("\\|")) {
                        boolean th = hasHead && r == 0;
                        o.append(th ? "<th>" : "<td>").append(mdInline(c.trim())).append(th ? "</th>" : "</td>");
                    }
                    o.append("</tr>\n");
                }
                o.append("</table>\n");
                i = j - 1;
                continue;
            }
            int h = 0; while (h < l.length() && h < 7 && l.charAt(h) == '#') h++;
            if (h > 0 && h < l.length() && l.charAt(h) == ' ') {       // 标题
                mdFlush(o, para);
                o.append("<h").append(h).append('>').append(mdInline(l.substring(h + 1)))
                 .append("</h").append(h).append(">\n");
                continue;
            }
            if (l.startsWith("---") || l.startsWith("***")) { mdFlush(o, para); o.append("<hr>\n"); continue; }
            if (l.startsWith("> ")) { mdFlush(o, para); o.append("<blockquote>").append(mdInline(l.substring(2))).append("</blockquote>\n"); continue; }
            if (l.startsWith("- ") || l.matches("^[0-9]+\\.[ ].*")) {  // 列表
                mdFlush(o, para);
                String t = l.startsWith("- ") ? l.substring(2) : l.replaceFirst("^[0-9]+\\.\\s+", "");
                o.append("<ul><li>").append(mdInline(t)).append("</li></ul>\n");
                continue;
            }
            para.add(l);
        }
        mdFlush(o, para);
        return o.toString();
    }

    static final String DOC_CSS = """
            :root{color-scheme:light dark}
            body{margin:0;padding:2rem 1rem;font:16px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",
                 "PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
                 background:#fafafa;color:#222}
            main{max-width:860px;margin:0 auto;background:#fff;padding:2.5rem 3rem;border-radius:12px;
                 box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 30px rgba(0,0,0,.04)}
            h1{font-size:1.9rem;border-bottom:2px solid #eee;padding-bottom:.5rem;margin-top:0}
            h2{font-size:1.35rem;margin-top:2rem;border-bottom:1px solid #f0f0f0;padding-bottom:.3rem}
            code{background:#f2f3f5;padding:.15em .4em;border-radius:4px;
                 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
            pre{background:#1e2127;color:#e6e6e6;padding:1rem 1.2rem;border-radius:8px;overflow-x:auto}
            pre code{background:none;color:inherit;padding:0}
            table{border-collapse:collapse;width:100%;margin:1rem 0}
            th,td{border:1px solid #e5e7eb;padding:.5rem .75rem;text-align:left;vertical-align:top}
            th{background:#f8f9fa;font-weight:600}
            blockquote{margin:1rem 0;padding:.6rem 1rem;border-left:4px solid #d0d7de;
                       background:#f6f8fa;color:#444;border-radius:0 6px 6px 0}
            hr{border:none;border-top:1px solid #eee;margin:2rem 0}
            a{color:#0969da}
            ul{margin:.4rem 0;padding-left:1.4rem}
            @media (prefers-color-scheme:dark){
              body{background:#0d1117;color:#e6edf3}
              main{background:#161b22;box-shadow:none}
              code{background:#21262d}
              th{background:#21262d} th,td{border-color:#30363d}
              blockquote{background:#161b22;border-color:#30363d;color:#c9d1d9}
              h1,h2{border-color:#30363d}
            }
            """;

    static byte[] apiDocPage() {
        String html = "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>番茄小说签名 API · 文档</title><style>" + DOC_CSS + "</style></head>"
                + "<body><main>" + mdToHtml(API_DOC_MD) + "</main></body></html>";
        return html.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** 从请求体里取一个字符串字段（极简解析，够用即可） */
    static String jget(String body, String key) {
        int i = body.indexOf("\"" + key + "\"");
        if (i < 0) return null;
        int a = body.indexOf('"', body.indexOf(':', i) + 1);
        if (a < 0) return null;
        int b = body.indexOf('"', a + 1);
        if (b < 0) return null;
        return body.substring(a + 1, b);
    }

    /** 把 .so 返回的多行签名文本（头名/值成对）转成 JSON 对象 */
    static String sigToJson(String sig) {
        if (sig == null) return "{}";
        String[] lines = sig.replace("\r\n", "\n").split("\n");
        StringBuilder b = new StringBuilder("{");
        int n = 0;
        for (int i = 0; i + 1 < lines.length; i += 2) {
            String k = lines[i].trim();
            if (k.isEmpty()) { i--; continue; }          // 容忍空行错位
            String v = lines[i + 1].trim();
            if (n++ > 0) b.append(',');
            b.append('"').append(jesc(k)).append("\":\"").append(jesc(v)).append('"');
        }
        return b.append('}').toString();
    }

    /** 收集本请求涉及的【所有】候选客户端 IP —— 防伪造的核心：任一个超限即拒绝 */
    static java.util.List<String> clientIps(com.sun.net.httpserver.HttpExchange ex) {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
        // Cloudflare 会覆盖/写入这两个，客户端无法伪造
        addIp(set, ex.getRequestHeaders().getFirst("CF-Connecting-IP"));
        addIp(set, ex.getRequestHeaders().getFirst("True-Client-IP"));
        addIp(set, ex.getRequestHeaders().getFirst("X-Real-IP"));
        // XFF 的【每一跳】都要计入（伪造的也计入——伪造者只会让自己更早被限）
        String xff = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff != null) {
            int n = 0;
            for (String part : xff.split(",")) { if (n++ >= 8) break; addIp(set, part); }
        }
        addIp(set, ex.getRequestHeaders().getFirst("CF-Pseudo-IPv4"));
        // socket 对端不可伪造；但容器内经隧道进来时它是 cf-gateway 的私网地址（所有用户共用），
        // 计入会把全部用户挤进同一个桶 ⇒ 【只有公网地址才计入】
        var ra = ex.getRemoteAddress();
        if (ra != null && ra.getAddress() != null && isPublic(ra.getAddress().getHostAddress()))
            addIp(set, ra.getAddress().getHostAddress());
        if (set.isEmpty()) set.add("unknown");
        return new java.util.ArrayList<>(set);
    }

    static void addIp(java.util.Set<String> set, String ip) {
        if (ip == null) return;
        ip = ip.trim();
        if (ip.isEmpty() || ip.length() > 45) return;
        if (ip.startsWith("::ffff:")) ip = ip.substring(7);
        set.add(ip);
    }

    /** 是否公网地址（私网/回环/链路本地/CGNAT 一律不算，用于识别"隧道代理"） */
    static boolean isPublic(String ip) {
        if (ip == null) return false;
        if (ip.indexOf(':') >= 0) {
            String l = ip.toLowerCase();
            return !(l.equals("::1") || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80"));
        }
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        try {
            int a = Integer.parseInt(p[0]), b = Integer.parseInt(p[1]);
            if (a == 0 || a == 10 || a == 127) return false;
            if (a == 172 && b >= 16 && b <= 31) return false;
            if (a == 192 && b == 168) return false;
            if (a == 169 && b == 254) return false;
            if (a == 100 && b >= 64 && b <= 127) return false;
            return true;
        } catch (Exception e) { return false; }
    }
    static String decryptKey;

    static String deviceId = "1571665370172347";
    static String installId = "1571665370176443";
    static String deviceCdid = "4f8527b1-1d6d-492b-8af4-6ee6caa645c8";

    static final String DIRECTORY_URL = "https://fanqienovel.com/api/reader/directory/detail";
    static final String SEARCH_URL = "https://novel.snssdk.com/api/novel/channel/homepage/search/search/v1/";

    static final int GROUP_SIZE = 50;
    static final Pattern IMG_PATTERN = Pattern.compile(
        "<img[^>]*\\bsrc\\s*=\\s*['\"]([^'\"]+)['\"][^>]*>", Pattern.CASE_INSENSITIVE
    );

    record Chapter(String itemId, String title, int order) {}
    record BookInfo(String bookId, String title, String author, String category, String score, String desc) {}
    record ImageInfo(byte[] data, String mime, String filename) {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("用法:");
            System.err.println("  search <关键词>");
            System.err.println("  download <book_id> [选项...]");
            System.err.println("");
            System.err.println("download 选项:");
            System.err.println("  -start=N, --start=N       起始章节（从1开始）");
            System.err.println("  -end=N, --end=N           结束章节");
            System.err.println("  --output=txt              输出TXT（默认EPUB）");
            System.err.println("  --book-name=名称          自定义书名");
            System.exit(1);
        }
        var cmd = args[0];
        var rest = new ArrayList<>(List.of(args));
        rest.removeFirst();
        switch (cmd) {
            case "search" -> handleSearch(String.join(" ", rest));
            case "download" -> handleDownload(rest);
            case "serve" -> {
                int port = rest.size() > 0 ? Integer.parseInt(rest.get(0)) : 8090;
                if (idleFQ == null) {
                    System.setErr(new PrintStream(new OutputStream() {public void write(int b){}}));
                    idleFQ = new IdleFQ(false);
                    System.setErr(System.err);
                }
                // ---- 准入控制参数（环境变量可覆盖）----
                final int  MAX_QUEUE    = Integer.parseInt(System.getenv().getOrDefault("FQ_MAX_QUEUE", "20"));
                final long PER_IP_MS    = Long.parseLong(System.getenv().getOrDefault("FQ_PER_IP_MS", "5000"));
                final int  MAX_INFLIGHT = MAX_QUEUE + 1;   // 1 个正在处理 + 最多 20 个排队

                System.out.println("[SERVE] 预热一次签名...");
                try { getFqSig("https://api5-normal-sinfonlineb.fqnovel.com/reading/crypt/registerkey?aid=1967"); } catch (Throwable te) {}
                System.out.println("[SERVE] 策略: 完全串行(禁止并行) | 最多排队 " + MAX_QUEUE
                        + " 个 | 单 IP 间隔 " + PER_IP_MS + "ms | 超出立即 503");

                // 串行闸门：只有 1 个许可（fair=true ⇒ 先到先得，天然 FIFO 排队）
                final java.util.concurrent.Semaphore worker = new java.util.concurrent.Semaphore(1, true);
                // 在途计数 = 正在处理 + 排队中
                final java.util.concurrent.atomic.AtomicInteger inflight = new java.util.concurrent.atomic.AtomicInteger();
                final java.util.concurrent.atomic.AtomicLong served   = new java.util.concurrent.atomic.AtomicLong();
                final java.util.concurrent.atomic.AtomicLong rejected = new java.util.concurrent.atomic.AtomicLong();

                com.sun.net.httpserver.HttpServer srv =
                        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(port), 64);

                srv.createContext("/health", ex -> jresp(ex, 200,
                        "{\"status\":\"ok\",\"inflight\":" + inflight.get()
                                + ",\"served\":" + served.get() + ",\"rejected\":" + rejected.get() + "}", null));

                // 根路径 → 渲染后的 API 文档（HTML）
                srv.createContext("/", ex -> {
                    byte[] page = apiDocPage();
                    ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                    ex.sendResponseHeaders(200, page.length);
                    try (java.io.OutputStream os = ex.getResponseBody()) { os.write(page); }
                });

                srv.createContext("/sign", ex -> {
                    try {
                        // 1) 先读 body、解析 url（不要占着排队名额等慢客户端）
                        String body = new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                        String url = jget(body, "url");
                        if (url == null || url.isBlank()) url = body.trim();   // 最简用法：body 直接就是 url
                        String hdr = jget(body, "header");
                        if (hdr == null) hdr = "";

                        if (url.isBlank()) { jresp(ex, 400, "{\"ok\":false,\"error\":\"missing url\"}", null); return; }

                        // 2) 排队名额：满了【立即】503，不进入等待
                        if (inflight.incrementAndGet() > MAX_INFLIGHT) {
                            inflight.decrementAndGet();
                            rejected.incrementAndGet();
                            jresp(ex, 503, "{\"ok\":false,\"error\":\"server overloaded\",\"queue\":" + MAX_QUEUE + "}", null);
                            return;
                        }
                        try {
                            // 3) 单 IP 限速 1 次 / PER_IP_MS（只在【被接纳】时打时间戳，
                            //    这样被 429/503 拒掉的请求不会把该 IP 的窗口顶住）
                            java.util.List<String> ips = clientIps(ex);
                            long now = System.currentTimeMillis();
                            long worst = 0; String worstIp = null;
                            for (String ip : ips) {                 // 任一个超限 ⇒ 拒绝
                                Long prev = IP_LAST.get(ip);
                                if (prev != null && now - prev < PER_IP_MS) {
                                    long w = PER_IP_MS - (now - prev);
                                    if (w > worst) { worst = w; worstIp = ip; }
                                }
                            }
                            if (worst > 0) {
                                long retry = Math.max(1, (worst + 999) / 1000);
                                rejected.incrementAndGet();
                                jresp(ex, 429, "{\"ok\":false,\"error\":\"rate limited\",\"retry_after\":" + retry
                                        + ",\"ip\":\"" + jesc(worstIp) + "\"}", String.valueOf(retry));
                                return;
                            }
                            for (String ip : ips) IP_LAST.put(ip, now);   // 接受 ⇒ 给所有 IP 打时间戳
                            if (IP_LAST.size() > 20000) {           // 顺手清理过期条目，防 map 无限增长
                                long cut = now - PER_IP_MS;
                                IP_LAST.entrySet().removeIf(e -> e.getValue() < cut);
                            }

                            // 4) 申请串行闸门 —— 这里就是"排队"
                            worker.acquire();
                            try {
                                String sig = getFqSig(url);
                                served.incrementAndGet();
                                jresp(ex, 200, "{\"ok\":true,\"headers\":" + sigToJson(sig) + "}", null);
                            } finally {
                                worker.release();
                            }
                        } finally {
                            inflight.decrementAndGet();
                        }
                    } catch (Throwable te) {
                        jresp(ex, 500, "{\"ok\":false,\"error\":\"internal\"}", null);
                    } finally {
                        ex.close();
                    }
                });

                // HttpServer 的线程只需要"托住"最多 MAX_INFLIGHT 个等待中的 handler，
                // 其余都是瞬时返回的拒绝请求 ⇒ 用 cached pool（线程复用，不会丢连接）。
                srv.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
                srv.start();
                System.out.println("[SERVE] listening :" + port);
                Thread.currentThread().join();
            }
            case "sign" -> {
                String u = String.join(" ", rest);
                if (idleFQ == null) {
                    System.setErr(new PrintStream(new OutputStream() {public void write(int b){}}));
                    idleFQ = new IdleFQ(false);
                    System.setErr(System.err);
                }
                String sg = getFqSig(u);
                System.out.println("__SIG_BEGIN__" + sg + "__SIG_END__");
            }
            default -> {
                System.err.println("未知命令: " + cmd);
                System.exit(1);
            }
        }
    }

    // ── Search ──────────────────────────────────────────

    static void handleSearch(String keyword) throws Exception {
        if (keyword.isBlank()) {
            System.err.println("关键词不能为空");
            System.exit(1);
        }
        String url = SEARCH_URL + "?q=" + URLEncoder.encode(keyword, StandardCharsets.UTF_8) + "&aid=1967";
        var json = fetchJson(url);
        var dataObj = json instanceof JsonValue.JsonObject jo ? jo.map().get("data") : null;
        var retData = dataObj != null ? optArray(dataObj, "ret_data") : new JsonValue.JsonArray(new ArrayList<>());

        var results = retData.list().stream()
                .map(v -> new BookInfo(
                        optStr(v, "book_id"),
                        optStr(v, "title"),
                        optStr(v, "author"),
                        optStr(v, "category"),
                        optStr(v, "score", "N/A"),
                        optStr(v, "abstract")))
                .toList();

        if (results.isEmpty()) {
            System.out.println("未找到相关书籍。");
            return;
        }
        System.out.println("共找到 " + results.size() + " 本小说：\n");
        System.out.printf("%-22s  %-20s  %-16s  %s%n", "Book ID", "书名", "作者", "评分");
        System.out.println("-".repeat(80));
        for (var r : results) {
            System.out.printf("%-22s  %-20s  %-16s  %s%n",
                    r.bookId(), truncate(r.title(), 20), truncate(r.author(), 16), r.score());
        }
    }

    // ── Download ────────────────────────────────────────

    static void handleDownload(List<String> args) throws Exception {
        if (args.isEmpty()) {
            System.err.println("用法: download <book_id> [-start=N] [-end=N] [--output=txt]");
            System.exit(1);
        }
        var bookId = args.getFirst();
        int start = 1, end = 0;
        boolean outputTxt = false;
        String cliBookName = null;
        int getMore = GROUP_SIZE;

        for (int i = 1; i < args.size(); i++) {
            var a = args.get(i);
            if (a.startsWith("--start=") || a.startsWith("-start="))
                start = Integer.parseInt(a.substring(a.indexOf("start=") + 6));
            else if (a.startsWith("--end=") || a.startsWith("-end="))
                end = Integer.parseInt(a.substring(a.indexOf("end=") + 4));
            else if (a.equals("--output=txt")) outputTxt = true;
            else if (a.startsWith("--book-name=")) cliBookName = a.substring(12);
        }

        var outDir = Path.of("output", bookId);
        Files.createDirectories(outDir);

        System.out.println("获取书籍信息...");
        String bookName = bookId;
        if (cliBookName != null) bookName = cliBookName;
        else {
            bookName = fetchBookNameFromPage(bookId);
            if (bookName.isBlank()) bookName = bookId;
        }
        ImageInfo coverImage = null;
        try {
            var coverUrl = fetchCoverUrl(bookId);
            if (coverUrl != null) coverImage = downloadImage(coverUrl);
        } catch (Exception ignored) {}
        if (coverImage == null) {
            try {
                var sUrl = SEARCH_URL + "?q=" + URLEncoder.encode(bookId, StandardCharsets.UTF_8) + "&aid=1967";
                var sJson = fetchJson(sUrl);
                var sData = sJson instanceof JsonValue.JsonObject sjo ? sjo.map().get("data") : null;
                var sRet = sData != null ? optArray(sData, "ret_data") : new JsonValue.JsonArray(new ArrayList<>());
                var match = sRet.list().stream()
                        .filter(v -> optStr(v, "book_id").equals(bookId)).findFirst();
                if (match.isPresent()) {
                    var thumb = optStr(match.get(), "thumb");
                    if (!thumb.isBlank()) coverImage = downloadImage(thumb);
                }
            } catch (Exception ignored) {}
        }

        System.out.println("获取目录...");
        var chapters = fetchChaptersWithFallback(bookId);
        if (chapters.isEmpty()) { System.err.println("获取目录失败"); System.exit(1); }

        int total = chapters.size();
        int startIdx = Math.max(1, start);
        int endIdx = end <= 0 ? total : end;
        if (startIdx > total) { System.err.println("起始章节 " + startIdx + " 超出范围"); System.exit(1); }
        if (endIdx > total) { System.out.println("结束章节 " + endIdx + " 超出范围，截断至 " + total); endIdx = total; }
        if (startIdx > endIdx) { System.err.println("起始章节 > 结束章节"); System.exit(1); }
        var selected = chapters.subList(startIdx - 1, endIdx);
        int totalChapters = selected.size();
        System.out.println("下载第 " + startIdx + " ~ " + endIdx + " 章（共 " + totalChapters + " 章）");

        // Init engine
        try {
            System.out.println("初始化签名引擎...");
            System.setErr(new PrintStream(new OutputStream() {public void write(int b){}}));
            idleFQ = new IdleFQ(false);
            System.setErr(System.err);
            System.out.println("获取解密密钥...");
            decryptKey = fetchDecryptKey();
            System.out.println("密钥已就绪");
        } catch (Exception e) {
            System.err.println("引擎初始化失败: " + e);
            if (idleFQ != null) try { idleFQ.destroy(); } catch (Exception ignored) {}
            System.exit(1);
        }

        var chapterContents = new ConcurrentHashMap<Integer, String>();
        var imageCache = new ConcurrentHashMap<String, ImageInfo>();

        for (int g = 0; g < totalChapters; g += getMore) {
            int gEnd = Math.min(g + getMore, totalChapters);
            List<Integer> failed = new ArrayList<>();
            for (int j = g; j < gEnd; j++) failed.add(j);
            System.out.println("  批次 " + ((g/getMore)+1) + " (第 " + (startIdx+g) + "-" + (startIdx+gEnd-1) + " 章): " + failed.size() + " 章");

            while (!failed.isEmpty()) {
                var ids = failed.stream().map(i -> selected.get(i).itemId()).collect(java.util.stream.Collectors.joining(","));
                Thread.sleep(2000);
                try {
                    var bc = fetchBatchContent(ids, bookId);
                    var iter = failed.iterator();
                    while (iter.hasNext()) {
                        int j = iter.next();
                        String raw = bc != null ? bc.get(selected.get(j).itemId()) : null;
                        if (raw == null || raw.isBlank()) continue;
                        String processed = outputTxt ? extractBlkText(raw) : blkToP(raw);
                        if (!outputTxt) processed = processImages(processed, imageCache);
                        chapterContents.put(j, processed);
                        iter.remove();
                    }
                } catch (Exception e) {
                    System.out.println("  批次 " + ((g/getMore)+1) + " 失败: " + e + "，" + failed.size() + " 章待重试");
                }
            }
            System.out.println("  批次 " + ((g/getMore)+1) + "/" + ((totalChapters+getMore-1)/getMore) + " 完成");
        }

        var ext = outputTxt ? ".txt" : ".epub";
        var outputPath = outDir.resolve(bookId + "_" + startIdx + "-" + endIdx + ext);
        generateOutput(outputPath.toString(), bookId, bookName, selected, totalChapters, outputTxt,
                       chapterContents, imageCache, coverImage);
        System.out.println("已保存: " + outputPath.toAbsolutePath());

        var tmpDir = Path.of(System.getProperty("java.io.tmpdir"));
        try (var files = Files.list(tmpDir)) {
            files.filter(p -> p.getFileName().toString().startsWith("fanqie_"))
                 .forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception ignored) {} });
        }
        if (idleFQ != null) try { idleFQ.destroy(); } catch (Exception ignored) {}
    }

    // ── FQ signed API methods ─────────────────────────────

    static String fetchDecryptKey() throws Exception {
        FqVariable var = new FqVariable();
        var.setServerDeviceId(deviceId);
        var.setInstallId(installId);
        var.setCdid(deviceCdid);
        FqCrypto crypto = new FqCrypto(FqCrypto.REG_KEY);
        String encContent = crypto.newRegisterKeyContent(var.getServerDeviceId(), "0");
        String url = FQ_BASE_URL + "/reading/crypt/registerkey" + buildFqQS();
        String sig = getFqSig(url);
        byte[] raw = fqHttpPost(url, sig, ("{\"content\":\"" + encContent + "\",\"keyver\":1}").getBytes(StandardCharsets.UTF_8));
        if (raw == null) throw new IOException("registerkey 返回空");
        String resp = tryGunzip(raw);
        if (resp == null) resp = new String(raw, StandardCharsets.UTF_8);
        try {
            var parsed = new JsonParser(resp).parse();
            if (parsed instanceof JsonValue.JsonObject root) {
                int code = root.integer("code", 0);
                if (code != 0) {
                    String message = root.str("message", "unknown error");
                    switch (code) {
                        case 1 -> throw new IOException("SYSTEM: 系统错误 (code=1)");
                        case 2 -> throw new IOException("INVALID_REQ: 无效请求 (code=2)");
                        case 100 -> throw new IOException("FAST_REJECT: 请求被快速拒绝 (code=100)");
                        case 110 -> throw new IOException("ILLEGAL_ACCESS: 非法访问，设备可能被封禁 (code=110)");
                        case 500000 -> throw new IOException("KEY_TOO_OLD: 密钥过期 (code=500000)");
                        case 500001 -> throw new IOException("ESCAPE_KEY: 逃逸密钥 (code=500001)");
                        case 500002 -> throw new IOException("VERIFY_FAIL: 验证失败 (code=500002)");
                        case 500003 -> { return ""; }
                        default -> throw new IOException("registerkey error: " + message + " (code=" + code + ")");
                    }
                }
            }
        } catch (IOException e) { throw e; } catch (Exception ignored) {}
        int p = resp.indexOf("\"key\"");
        if (p < 0) throw new IOException("registerkey 响应无key字段");
        int c = resp.indexOf(':', p + 5);
        int sq = resp.indexOf('"', c + 1), eq = resp.indexOf('"', sq + 1);
        if (sq < 0 || eq <= sq) throw new IOException("key格式错误");
        String encryptedKey = resp.substring(sq + 1, eq);
        String realKey = FqCrypto.getRealKey(encryptedKey);
        return realKey.length() > 32 ? realKey.substring(0, 32) : realKey;
    }

    static Map<String, String> fetchBatchContent(String itemIds, String bookId) throws Exception {
        Map<String, String> params = buildFqParams();
        params.put("item_ids", itemIds);
        params.put("key_register_ts", "0");
        params.put("book_id", bookId);
        params.put("req_type", "1");
        String url = FQ_BASE_URL + "/reading/reader/batch_full/v1" + buildFqQS(params);
        String sig = getFqSig(url);
        byte[] raw = fqHttpGet(url, sig);
        if (raw == null || raw.length == 0) throw new IOException("batch_full 返回空 (url=" + url + ")");
        String json = tryGunzip(raw);
        if (json == null) json = new String(raw, StandardCharsets.UTF_8);
        Map<String, String> results = new HashMap<>();
        try {
            var parsed = new JsonParser(json).parse();
            if (parsed instanceof JsonValue.JsonObject root) {
                int code = root.integer("code", 0);
                if (code != 0) {
                    String message = root.str("message", "unknown error");
                    switch (code) {
                        case 100 -> throw new IOException("FAST_REJECT (code=100)");
                        case 110 -> throw new IOException("ILLEGAL_ACCESS (code=110)");
                        case 111 -> throw new IOException("HIT_VERIFY_CODE (code=111)");
                        case 101004 -> throw new IOException("BOOK_NOT_EXIST (code=101004)");
                        case 101005 -> throw new IOException("CHAPTER_DATA_GET_ERROR (code=101005)");
                        case 101009 -> throw new IOException("USER_NO_PERMISSION (code=101009)");
                        case 101017 -> throw new IOException("CONTENT_VERIFYING (code=101017)");
                        case 101021 -> throw new IOException("BOOK_FULLLY_REMOVE (code=101021)");
                        default -> {
                            if (code >= 100 && code <= 111)
                                throw new IOException("ReaderApiERR: " + message + " (code=" + code + ")");
                            System.out.println("  [batch] 响应码=" + code + " " + message);
                            var d = root.get("data");
                            if (!(d instanceof JsonValue.JsonObject) || ((JsonValue.JsonObject)d).map().isEmpty())
                                throw new IOException("响应错误 " + code + ": " + message);
                        }
                    }
                }
                var data = root.get("data");
                if (data instanceof JsonValue.JsonObject dataObj) {
                    for (var entry : dataObj.map().entrySet()) {
                        var itemId = entry.getKey();
                        if (entry.getValue() instanceof JsonValue.JsonObject itemObj) {
                            int cryptStatus = itemObj.integer("crypt_status", 0);
                            var contentStr = itemObj.str("content");
                            if (contentStr != null && !contentStr.isBlank()) {
                                try {
                                    String decrypted = switch (cryptStatus) {
                                        case 1, 2 -> contentStr;
                                        default -> FqCrypto.decryptAndDecompressContent(contentStr, decryptKey);
                                    };
                                    results.put(itemId, decrypted);
                                } catch (Exception ex) {
                                    System.out.println("  [batch] 解密失败 itemId=" + itemId + ": " + ex);
                                    results.put(itemId, "");
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException e) { throw e; } catch (Exception e) { throw new IOException("JSON解析失败: " + e); }
        if (results.isEmpty()) {
            System.out.println("  [batch] 完整响应: " + json.substring(0, Math.min(2000, json.length())));
        }
        return results;
    }

    // ── HTTP ──────────────────────────────────────────────

    static byte[] fqHttpGet(String url, String sig) throws Exception {
        HttpURLConnection c = openFqConn(url);
        c.setRequestMethod("GET"); c.setConnectTimeout(15000); c.setReadTimeout(30000);
        c.setRequestProperty("User-Agent", FQ_UA); c.setRequestProperty("Cookie", FQ_COOKIE);
        if (sig != null && !sig.isEmpty()) {
            String[] lines = sig.split("\n");
            for (int i = 0; i < lines.length - 1; i += 2)
                c.setRequestProperty(lines[i].trim(), lines[i + 1].trim());
        }
        for (var e : buildFqHeaders().entrySet()) {
            if (!e.getKey().equals("Cookie") && !e.getKey().equals("User-Agent"))
                c.setRequestProperty(e.getKey(), e.getValue());
        }
        int code = c.getResponseCode();
        System.out.println("  [HTTP] " + url.substring(0, Math.min(120, url.length())) + " → " + code);
        InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
        if (is == null) return null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        is.close(); return bos.toByteArray();
    }

    static byte[] fqHttpPost(String url, String sig, byte[] body) throws Exception {
        HttpURLConnection c = openFqConn(url);
        c.setRequestMethod("POST"); c.setConnectTimeout(15000); c.setReadTimeout(30000);
        c.setDoOutput(true); c.setRequestProperty("Content-Type", "application/json");
        if (sig != null && !sig.isEmpty()) {
            String[] lines = sig.split("\n");
            for (int i = 0; i < lines.length - 1; i += 2)
                c.setRequestProperty(lines[i].trim(), lines[i + 1].trim());
        }
        for (var e : buildFqHeaders().entrySet()) {
            if (!e.getKey().equals("Content-Type"))
                c.setRequestProperty(e.getKey(), e.getValue());
        }
        c.getOutputStream().write(body); c.getOutputStream().flush();
        int code = c.getResponseCode();
        System.out.println("  [HTTP] POST " + url.substring(0, Math.min(120, url.length())) + " → " + code);
        InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
        if (is == null) return null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        is.close(); return bos.toByteArray();
    }

    static HttpURLConnection openFqConn(String url) throws Exception {
        return (HttpURLConnection) new URL(url).openConnection();
    }

    static synchronized String getFqSig(String url) {
        Map<String, String> h = buildFqHeaders();
        StringBuilder sb = new StringBuilder();
        for (var e : h.entrySet())
            sb.append(e.getKey()).append("\r\n").append(e.getValue()).append("\r\n");
        String hs = sb.toString();
        if (hs.endsWith("\r\n")) hs = hs.substring(0, hs.length() - 2);
        String _sig = idleFQ.generateSignature(url, hs);
        try {
            java.nio.file.Files.writeString(java.nio.file.Path.of("/tmp/fq_sig_capture.txt"),
                "=== URL ===\n" + url + "\n=== HEADERS ===\n" + hs + "\n=== SIG ===\n" + _sig + "\n",
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
        System.out.println("[CAPTURE] url=" + url);
        System.out.println("[CAPTURE] headers_len=" + hs.length());
        System.out.println("[CAPTURE] sig=" + _sig);
        return _sig;
    }

    static Map<String, String> buildFqParams() {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("iid", installId); p.put("device_id", deviceId); p.put("ac", "wifi");
        p.put("channel", "googleplay"); p.put("aid", "1967"); p.put("app_name", "novelapp");
        p.put("version_code", "68132"); p.put("version_name", "6.8.1.32");
        p.put("device_platform", "android"); p.put("os", "android"); p.put("ssmix", "a");
        p.put("device_type", "OnePlus11"); p.put("device_brand", "OnePlus");
        p.put("language", "zh"); p.put("os_api", "32"); p.put("os_version", "12");
        p.put("manifest_version_code", "68132"); p.put("resolution", "3200*1440");
        p.put("dpi", "640"); p.put("update_version_code", "68132");
        p.put("_rticket", String.valueOf(System.currentTimeMillis()));
        p.put("host_abi", "arm64-v8a"); p.put("dragon_device_type", "phone");
        p.put("pv_player", "68132"); p.put("compliance_status", "0");
        p.put("need_personal_recommend", "1"); p.put("player_so_load", "1");
        p.put("is_android_pad_screen", "0"); p.put("rom_version", "V291IR+release-keys");
        p.put("cdid", deviceCdid);
        return p;
    }

    static String buildFqQS() { return buildFqQS(buildFqParams()); }

    static String buildFqQS(Map<String, String> params) {
        StringBuilder sb = new StringBuilder("?");
        boolean first = true;
        for (var e : params.entrySet()) {
            if (!first) sb.append("&");
            sb.append(e.getKey()).append("=").append(e.getValue());
            first = false;
        }
        return sb.toString();
    }

    static Map<String, String> buildFqHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Cookie", FQ_COOKIE); h.put("User-Agent", FQ_UA);
        h.put("Accept", "application/json; charset=utf-8");
        h.put("Accept-Encoding", "gzip"); h.put("x-xs-from-web", "0");
        h.put("x-ss-req-ticket", String.valueOf(System.currentTimeMillis()));
        h.put("x-reading-request", System.currentTimeMillis() + "-" + (int)(Math.random() * 2e9));
        h.put("x-vc-bdturing-sdk-version", "3.7.2.cn");
        h.put("lc", "101"); h.put("sdk-version", "2");
        h.put("passport-sdk-version", "50564");
        h.put("x-tt-store-region", "cn-zj"); h.put("x-tt-store-region-src", "did");
        return h;
    }

    static String tryGunzip(byte[] data) {
        if (data == null || data.length < 2) return null;
        if ((data[0] & 0xff) != 0x1f || (data[1] & 0xff) != 0x8b) return null;
        try {
            GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(data));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int n;
            while ((n = gis.read(buf)) != -1) bos.write(buf, 0, n);
            gis.close(); return bos.toString(StandardCharsets.UTF_8);
        } catch (Exception e) { return null; }
    }

    // ── Content processing ────────────────────────────────

    static String extractBlkText(String html) {
        StringBuilder sb = new StringBuilder();
        int idx = 0;
        boolean first = true;
        while (true) {
            int st = html.indexOf("<blk", idx);
            if (st < 0) break;
            int ct = html.indexOf(">", st);
            if (ct < 0) break;
            int en = html.indexOf("</blk>", ct);
            if (en < 0) { sb.append(html.substring(ct + 1)); break; }
            String blk = html.substring(ct + 1, en);
            if (first) { first = false; idx = en + 6; continue; }
            sb.append(blk).append("\n");
            idx = en + 6;
        }
        String result = sb.toString().replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&apos;", "'")
                .replace("&nbsp;", " ");
        result = result.replaceAll("(?i)<br\\s*/?>", "\n");
        result = result.replaceAll("<[^>]+>", "");
        return result.strip();
    }

    static String blkToP(String html) {
        String result = html.replaceAll("(?i)<blk[^>]*>", "<p>");
        result = result.replaceAll("(?i)</blk>", "</p>");
        result = result.replaceAll("(?i)<imge[^>]*/>", "");
        return result;
    }

    static String processImages(String html, ConcurrentHashMap<String, ImageInfo> cache) {
        var matcher = IMG_PATTERN.matcher(html);
        var sb = new StringBuffer();
        while (matcher.find()) {
            String src = matcher.group(1);
            String newSrc = downloadAndCacheImage(src, cache);
            String tag = matcher.group(0);
            String rewritten = tag.replace(src, newSrc);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(rewritten));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    static ImageInfo downloadImage(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) return null;
        try {
            var req = HttpRequest.newBuilder()
                    .uri(URI.create(url)).header("User-Agent", UA).GET()
                    .timeout(Duration.ofSeconds(10)).build();
            var resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() == 200) {
                byte[] data = resp.body();
                var mimeAndExt = sniffMime(data);
                if (mimeAndExt[0].equals("application/octet-stream")) return null;
                String hash = sha1Hex(url);
                return new ImageInfo(data, mimeAndExt[0], "images/" + hash + mimeAndExt[1]);
            }
        } catch (Exception ignored) {}
        return null;
    }

    static String downloadAndCacheImage(String url, ConcurrentHashMap<String, ImageInfo> cache) {
        var existing = cache.get(url);
        if (existing != null) return existing.filename();
        if (!url.startsWith("http://") && !url.startsWith("https://")) return url;
        try {
            var req = HttpRequest.newBuilder()
                    .uri(URI.create(url)).header("User-Agent", UA).GET()
                    .timeout(Duration.ofSeconds(10)).build();
            var resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() == 200) {
                byte[] data = resp.body();
                var mimeAndExt = sniffMime(data);
                String mime = mimeAndExt[0]; String ext = mimeAndExt[1];
                if (mime.equals("application/octet-stream")) return url;
                String hash = sha1Hex(url);
                String filename = "images/" + hash + ext;
                var info = new ImageInfo(data, mime, filename);
                var prev = cache.putIfAbsent(url, info);
                return prev != null ? prev.filename() : filename;
            }
        } catch (Exception ignored) {}
        return url;
    }

    static String[] sniffMime(byte[] bytes) {
        if (bytes.length >= 3 && bytes[0] == (byte)0xFF && bytes[1] == (byte)0xD8 && bytes[2] == (byte)0xFF)
            return new String[]{"image/jpeg", ".jpg"};
        if (bytes.length >= 8 && bytes[0] == (byte)0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47)
            return new String[]{"image/png", ".png"};
        if (bytes.length >= 6 && bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46)
            return new String[]{"image/gif", ".gif"};
        if (bytes.length >= 12 && bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46)
            return new String[]{"image/webp", ".webp"};
        return new String[]{"application/octet-stream", ""};
    }

    // ── EPUB generation ─────────────────────────────────

    static void generateOutput(String outputPath, String bookId, String bookName,
                                List<Chapter> selected, int totalChapters, boolean outputTxt,
                                ConcurrentHashMap<Integer, String> chapterContents,
                                ConcurrentHashMap<String, ImageInfo> imageCache,
                                ImageInfo coverImage) throws Exception {
        if (outputTxt) {
            var sb = new StringBuilder();
            for (int i = 0; i < totalChapters; i++) {
                var content = chapterContents.get(i);
                if (content != null && !content.isBlank()) {
                    sb.append(selected.get(i).title()).append("\n\n");
                    sb.append(content).append("\n\n\n");
                } else {
                    sb.append(selected.get(i).title()).append("\n\n[获取失败]\n\n\n");
                }
            }
            Files.writeString(Path.of(outputPath), sb.toString(), StandardCharsets.UTF_8);
        } else {
            System.out.println("\n生成 EPUB...");
            generateEpub(outputPath, bookId, bookName, selected, chapterContents, imageCache, coverImage, totalChapters);
        }
    }

    static void generateEpub(String outputPath, String bookId, String bookName, List<Chapter> chapters,
                              ConcurrentHashMap<Integer, String> contents,
                              ConcurrentHashMap<String, ImageInfo> imageCache,
                              ImageInfo coverImage, int totalChapters) throws Exception {
        try (var fos = Files.newOutputStream(Path.of(outputPath));
             var zos = new ZipOutputStream(fos)) {
            zos.setLevel(9);
            byte[] mimetype = "application/epub+zip".getBytes(StandardCharsets.UTF_8);
            var mimetypeEntry = new ZipEntry("mimetype");
            mimetypeEntry.setMethod(ZipEntry.STORED); mimetypeEntry.setSize(mimetype.length);
            mimetypeEntry.setCompressedSize(mimetype.length);
            var crc = new CRC32(); crc.update(mimetype); mimetypeEntry.setCrc(crc.getValue());
            mimetypeEntry.setExtra(new byte[0]);
            zos.putNextEntry(mimetypeEntry); zos.write(mimetype); zos.closeEntry();

            zos.putNextEntry(new ZipEntry("META-INF/container.xml"));
            zos.write(buildContainerXml().getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("OEBPS/stylesheet.css"));
            zos.write(getCss().getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            String coverImageId = null, coverHref = null;
            if (coverImage != null) {
                coverHref = "cover.xhtml";
                zos.putNextEntry(new ZipEntry("OEBPS/" + coverHref));
                zos.write(buildCoverXhtml(bookName, coverImage.filename()).getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
                zos.putNextEntry(new ZipEntry("OEBPS/" + coverImage.filename()));
                zos.write(coverImage.data()); zos.closeEntry();
                coverImageId = "cover-image";
                imageCache.putIfAbsent("__cover__", coverImage);
            }

            var itemIds = new ArrayList<String>();
            for (int i = 0; i < totalChapters; i++) {
                var ch = i < chapters.size() ? chapters.get(i) : null;
                String title = ch != null ? ch.title() : "章节" + (i + 1);
                String body = contents.getOrDefault(i, "");
                zos.putNextEntry(new ZipEntry("OEBPS/" + String.format("chapter_%05d.xhtml", i + 1)));
                zos.write(buildChapterXhtml(title, body).getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
                itemIds.add(String.format("chapter_%05d.xhtml", i + 1));
            }

            String navHref = "nav.xhtml";
            zos.putNextEntry(new ZipEntry("OEBPS/" + navHref));
            zos.write(buildNavXhtml(bookName, chapters, totalChapters).getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            for (var entry : imageCache.entrySet()) {
                if ("__cover__".equals(entry.getKey())) continue;
                var info = entry.getValue();
                zos.putNextEntry(new ZipEntry("OEBPS/" + info.filename()));
                zos.write(info.data()); zos.closeEntry();
            }

            zos.putNextEntry(new ZipEntry("OEBPS/content.opf"));
            zos.write(buildOpfXml(bookId, bookName, chapters, imageCache, itemIds, coverHref, navHref, totalChapters)
                     .getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("OEBPS/toc.ncx"));
            zos.write(buildNcxXml(bookId, bookName, chapters, itemIds, totalChapters)
                     .getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
    }

    static String buildContainerXml() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             + "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">\n"
             + "  <rootfiles>\n"
             + "    <rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\"/>\n"
             + "  </rootfiles>\n"
             + "</container>\n";
    }

    static String buildOpfXml(String bookId, String bookName, List<Chapter> chapters,
                               ConcurrentHashMap<String, ImageInfo> imageCache,
                               List<String> itemIds, String coverHref, String navHref, int totalChapters) {
        var sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<package xmlns=\"http://www.idpf.org/2007/opf\" version=\"3.0\" unique-identifier=\"BookId\">\n");
        sb.append("  <metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n");
        sb.append("    <dc:identifier id=\"BookId\">").append(xmlEscape(bookId)).append("</dc:identifier>\n");
        sb.append("    <dc:title>").append(xmlEscape(bookName)).append("</dc:title>\n");
        sb.append("    <dc:language>zh</dc:language>\n");
        if (coverHref != null) {
            sb.append("    <meta name=\"cover\" content=\"cover-image\"/>\n");
            sb.append("    <meta property=\"rendition:cover-image\" content=\"cover-image\"/>\n");
        }
        sb.append("    <meta property=\"dcterms:modified\">").append(Instant.now().toString()).append("</meta>\n");
        sb.append("  </metadata>\n");
        sb.append("  <manifest>\n");
        sb.append("    <item id=\"ncx\" href=\"toc.ncx\" media-type=\"application/x-dtbncx+xml\"/>\n");
        sb.append("    <item id=\"css\" href=\"stylesheet.css\" media-type=\"text/css\"/>\n");
        if (coverHref != null)
            sb.append("    <item id=\"cover\" href=\"").append(coverHref).append("\" media-type=\"application/xhtml+xml\"/>\n");
        if (navHref != null)
            sb.append("    <item id=\"nav\" href=\"").append(navHref).append("\" media-type=\"application/xhtml+xml\" properties=\"nav\"/>\n");
        for (int i = 0; i < totalChapters; i++)
            sb.append("    <item id=\"ch_").append(String.format("%05d", i + 1))
              .append("\" href=\"").append(itemIds.get(i)).append("\" media-type=\"application/xhtml+xml\"/>\n");
        int imgIdx = 0;
        for (var entry : imageCache.entrySet()) {
            var info = entry.getValue();
            var isCover = entry.getKey().equals("__cover__");
            var id = isCover ? "cover-image" : String.format("img_%04d", imgIdx++);
            sb.append("    <item id=\"").append(id).append("\" href=\"").append(info.filename())
              .append("\" media-type=\"").append(info.mime()).append("\"")
              .append(isCover ? " properties=\"cover-image\"" : "")
              .append("/>\n");
        }
        sb.append("  </manifest>\n");
        sb.append("  <spine page-progression-direction=\"ltr\" toc=\"ncx\">\n");
        if (coverHref != null) sb.append("    <itemref idref=\"cover\"/>\n");
        if (navHref != null) sb.append("    <itemref idref=\"nav\"/>\n");
        for (int i = 0; i < totalChapters; i++)
            sb.append("    <itemref idref=\"ch_").append(String.format("%05d", i + 1)).append("\"/>\n");
        sb.append("  </spine>\n</package>\n");
        return sb.toString();
    }

    static String buildNcxXml(String bookId, String bookName, List<Chapter> chapters,
                               List<String> itemIds, int totalChapters) {
        var sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<!DOCTYPE ncx PUBLIC \"-//NISO//DTD ncx 2005-1//EN\" \"http://www.daisy.org/z3986/2005/ncx-2005-1.dtd\">\n");
        sb.append("<ncx xmlns=\"http://www.daisy.org/z3986/2005/ncx/\" version=\"2005-1\">\n");
        sb.append("  <head>\n");
        sb.append("    <meta name=\"dtb:uid\" content=\"").append(xmlEscape(bookId)).append("\"/>\n");
        sb.append("    <meta name=\"dtb:depth\" content=\"1\"/>\n");
        sb.append("    <meta name=\"dtb:totalPageCount\" content=\"0\"/>\n");
        sb.append("    <meta name=\"dtb:maxPageNumber\" content=\"0\"/>\n");
        sb.append("  </head>\n");
        sb.append("  <docTitle><text>").append(xmlEscape(bookName)).append("</text></docTitle>\n");
        sb.append("  <navMap>\n");
        for (int i = 0; i < totalChapters; i++) {
            var ch = i < chapters.size() ? chapters.get(i) : null;
            String title = ch != null ? ch.title() : "章节" + (i + 1);
            sb.append("    <navPoint id=\"navpoint-").append(i + 1).append("\" playOrder=\"").append(i + 1).append("\">\n");
            sb.append("      <navLabel><text>").append(xmlEscape(title)).append("</text></navLabel>\n");
            sb.append("      <content src=\"").append(itemIds.get(i)).append("\"/>\n");
            sb.append("    </navPoint>\n");
        }
        sb.append("  </navMap>\n</ncx>\n");
        return sb.toString();
    }

    static String buildChapterXhtml(String title, String body) {
        String escapedTitle = xmlEscape(title);
        String wrapped = body;
        if (!body.contains("<p") && !body.contains("<div") && !body.contains("<h")) {
            var w = new StringBuilder();
            for (String line : body.split("\n")) {
                line = line.strip();
                if (!line.isEmpty()) w.append("<p>").append(line).append("</p>\n");
            }
            wrapped = w.toString();
        }
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
             + "<!DOCTYPE html>\n"
             + "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"zh\" xml:lang=\"zh\">\n"
             + "<head><meta charset=\"utf-8\"/><title>" + escapedTitle + "</title>\n"
             + "<link href=\"stylesheet.css\" rel=\"stylesheet\" type=\"text/css\"/></head>\n"
             + "<body>\n<h1>" + escapedTitle + "</h1>\n<div class=\"content\">\n"
             + wrapped + "\n</div>\n</body>\n</html>\n";
    }

    static String buildNavXhtml(String bookName, List<Chapter> chapters, int totalChapters) {
        var ol = new StringBuilder();
        for (int i = 0; i < totalChapters; i++) {
            var ch = i < chapters.size() ? chapters.get(i) : null;
            String title = ch != null ? ch.title() : "章节" + (i + 1);
            String fid = String.format("chapter_%05d.xhtml", i + 1);
            ol.append("<li><a href=\"").append(fid).append("\">").append(xmlEscape(title)).append("</a></li>\n");
        }
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
             + "<!DOCTYPE html>\n"
             + "<html xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:epub=\"http://www.idpf.org/2007/ops\" lang=\"zh\" xml:lang=\"zh\">\n"
             + "<head><meta charset=\"utf-8\"/><title>" + xmlEscape(bookName) + "</title>\n"
             + "<link href=\"stylesheet.css\" rel=\"stylesheet\" type=\"text/css\"/></head>\n"
             + "<body>\n"
             + "<nav epub:type=\"toc\" id=\"toc\">\n"
             + "  <h1 id=\"toc-title\">" + xmlEscape(bookName) + "</h1>\n"
             + "  <ol>\n" + ol + "  </ol>\n"
             + "</nav>\n"
             + "</body>\n</html>\n";
    }

    static String buildCoverXhtml(String bookName, String imagePath) {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
             + "<!DOCTYPE html>\n"
             + "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"zh\" xml:lang=\"zh\">\n"
             + "<head><title>" + xmlEscape(bookName) + "</title>\n"
             + "<link href=\"stylesheet.css\" rel=\"stylesheet\" type=\"text/css\"/></head>\n"
             + "<body>\n<div style=\"text-align:center;padding:2em;\">\n"
             + "<img src=\"" + xmlEscape(imagePath) + "\" alt=\"Cover\" style=\"max-width:100%;height:auto;\"/>\n"
             + "</div>\n</body>\n</html>\n";
    }

    static String getCss() {
        return "body { font-family: serif; line-height: 1.8; padding: 1em; color: #000; }\n"
             + "p { text-indent: 2em; margin: 0.3em 0; line-height: 1.8; }\n"
             + "h1 { text-align: center; font-size: 1.4em; margin: 1em 0; }\n"
             + "img { max-width: 100%; height: auto; display: block; margin: 0.5em auto; }\n"
             + ".content { max-width: 35em; margin: 0 auto; }\n";
    }

    // ── Content extraction ───────────────────────────────

    static String fetchBookNameFromPage(String bookId) {
        try {
            var state = parsePageState(bookId);
            if (state instanceof JsonValue.JsonObject so) {
                var page = so.get("page");
                if (page instanceof JsonValue.JsonObject p)
                    return p.str("bookName");
            }
        } catch (Exception ignored) {}
        return "";
    }

    static String fetchCoverUrl(String bookId) throws Exception {
        var html = fetchHtml("https://fanqienovel.com/page/" + bookId);
        var ldUrl = extractLdJsonCover(html);
        if (ldUrl != null) return ldUrl;
        var state = parsePageState(bookId);
        if (state instanceof JsonValue.JsonObject jo) {
            var page = jo.get("page");
            if (page instanceof JsonValue.JsonObject p) {
                var url = p.str("thumbUrl");
                if (url != null && !url.isBlank()) return url;
                var thumbUri = p.str("thumbUri");
                if (thumbUri != null && !thumbUri.isBlank()) return thumbUri;
            }
        }
        return null;
    }

    // ── Directory ────────────────────────────────────────

    static List<Chapter> fetchChaptersWithFallback(String bookId) {
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                if (attempt > 0) Thread.sleep(1000L * attempt);
                var dJson = fetchJson(DIRECTORY_URL + "?bookId=" + bookId);
                var dData = dJson instanceof JsonValue.JsonObject djo ? djo.map().get("data") : null;
                var chapters = extractChapters(dData);
                if (!chapters.isEmpty()) return chapters;
            } catch (Exception ignored) {}
        }
        try {
            var state = parsePageState(bookId);
            if (state instanceof JsonValue.JsonObject so) {
                var page = so.get("page");
                if (page != null) {
                    var chapters = extractChapters(page);
                    if (!chapters.isEmpty()) return chapters;
                }
            }
        } catch (Exception ignored) {}
        return new ArrayList<>();
    }

    static List<Chapter> extractChapters(JsonValue data) {
        var list = new ArrayList<Chapter>();
        if (data == null) return list;
        if (list.isEmpty()) {
            for (var key : new String[]{"chapterList", "chapter_list", "chapters", "items", "list", "item_list"}) {
                var arr = optArray(data, key);
                if (!arr.list().isEmpty()) {
                    int idx = 1;
                    for (var ch : arr.list()) {
                        var itemId = optStr(ch, "itemId");
                        if (itemId.isBlank()) itemId = optStr(ch, "item_id");
                        if (!itemId.isBlank()) list.add(new Chapter(itemId, optStr(ch, "title"), idx++));
                    }
                    break;
                }
            }
        }
        if (list.isEmpty()) {
            var cv = data instanceof JsonValue.JsonObject jo ? jo.map().get("chapterListWithVolume") : null;
            if (cv instanceof JsonValue.JsonArray cva) {
                for (var vol : cva.list()) {
                    if (vol instanceof JsonValue.JsonArray va) {
                        for (var ch : va.list()) {
                            var itemId = optStr(ch, "itemId");
                            var title = optStr(ch, "title");
                            var orderStr = optStr(ch, "realChapterOrder");
                            int order = 0;
                            try { order = Integer.parseInt(orderStr); } catch (Exception ignored) {}
                            if (!itemId.isBlank()) list.add(new Chapter(itemId, title, order));
                        }
                    }
                }
            }
        }
        if (list.isEmpty()) {
            var inner = data instanceof JsonValue.JsonObject jo ? jo.get("data") : null;
            if (inner instanceof JsonValue.JsonObject) {
                for (var key : new String[]{"list", "chapterList", "chapter_list", "items", "item_list", "chapters"}) {
                    var arr = optArray(inner, key);
                    if (!arr.list().isEmpty()) {
                        int idx = 1;
                        for (var ch : arr.list()) {
                            var itemId = optStr(ch, "itemId");
                            if (itemId.isBlank()) itemId = optStr(ch, "item_id");
                            if (!itemId.isBlank()) list.add(new Chapter(itemId, optStr(ch, "title"), idx++));
                        }
                        break;
                    }
                }
            }
        }
        return list;
    }

    // ── HTTP + JSON helpers ─────────────────────────────

    static String fetchHtml(String url) throws Exception {
        var req = HttpRequest.newBuilder().uri(URI.create(url))
                .header("User-Agent", UA)
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .GET().timeout(Duration.ofSeconds(15)).build();
        var resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) throw new RuntimeException("HTTP " + resp.statusCode());
        return resp.body();
    }

    static JsonValue fetchJson(String url) throws Exception {
        var req = HttpRequest.newBuilder().uri(URI.create(url))
                .header("User-Agent", UA)
                .header("Accept", "application/json, text/plain, */*")
                .GET().timeout(Duration.ofSeconds(15)).build();
        var resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) throw new RuntimeException("HTTP " + resp.statusCode());
        return new JsonParser(resp.body()).parse();
    }

    static JsonValue parsePageState(String bookId) throws Exception {
        var html = fetchHtml("https://fanqienovel.com/page/" + bookId);
        var nextData = extractScriptJson(html, "__NEXT_DATA__");
        if (nextData != null) return nextData;
        return extractScriptJson(html, "__INITIAL_STATE__");
    }

    static JsonValue extractScriptJson(String html, String scriptId) {
        var marker = scriptId;
        int start = html.indexOf(marker);
        if (start < 0) return null;
        start = html.indexOf('{', start + marker.length());
        if (start < 0) return null;
        int depth = 0, end = start;
        boolean inStr = false;
        for (int i = start; i < html.length(); i++) {
            char c = html.charAt(i);
            if (inStr) { if (c == '\\') i++; else if (c == '"') inStr = false; }
            else if (c == '"') inStr = true;
            else if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) { end = i + 1; break; } }
        }
        if (end <= start) return null;
        try { return new JsonParser(html.substring(start, end)).parse(); } catch (Exception e) { return null; }
    }

    static String extractLdJsonCover(String html) {
        var m = Pattern.compile(
            "<script[^>]*type=\"application/ld\\+json\"[^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE).matcher(html);
        while (m.find()) {
            try {
                var parsed = new JsonParser(m.group(1)).parse();
                if (parsed instanceof JsonValue.JsonObject jo) {
                    for (var key : List.of("image", "images")) {
                        var v = jo.map().get(key);
                        if (v instanceof JsonValue.JsonArray arr) {
                            for (var item : arr.list()) {
                                if (item instanceof JsonValue.JsonString s) {
                                    var url = s.value().trim();
                                    if (!url.isEmpty() && (url.startsWith("http://") || url.startsWith("https://"))) return url;
                                }
                            }
                        } else if (v instanceof JsonValue.JsonString s) {
                            var url = s.value().trim();
                            if (!url.isEmpty() && (url.startsWith("http://") || url.startsWith("https://"))) return url;
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    static String optStr(JsonValue val, String key) {
        if (val instanceof JsonValue.JsonObject obj) {
            var v = obj.map().get(key);
            if (v instanceof JsonValue.JsonString s) return s.value();
        }
        return "";
    }

    static String optStr(JsonValue val, String key, String def) {
        var s = optStr(val, key);
        return s.isEmpty() ? def : s;
    }

    static JsonValue.JsonArray optArray(JsonValue val, String key) {
        if (val instanceof JsonValue.JsonObject obj) {
            var v = obj.map().get(key);
            if (v instanceof JsonValue.JsonArray a) return a;
        }
        return new JsonValue.JsonArray(new ArrayList<>());
    }

    static String truncate(String s, int max) {
        if (s == null || s.length() <= max) return s;
        return s.substring(0, max - 1) + "…";
    }

    // ── Utility ─────────────────────────────────────────

    static String xmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    static String sha1Hex(String input) {
        try {
            var md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            var sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return Integer.toHexString(input.hashCode()); }
    }

    static int findStrEnd(String s, int start) {
        boolean esc = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') return i;
        }
        return s.length();
    }

    static String decodeUnicode(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\\' && i + 5 < s.length() && s.charAt(i + 1) == 'u') {
                sb.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                i += 5;
            } else sb.append(s.charAt(i));
        }
        return sb.toString();
    }

    static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
