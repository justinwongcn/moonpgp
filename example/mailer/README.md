# example/mailer — 发送 PGP 签名且加密的邮件

一条命令:撰写邮件(正文 + 附件)→ PGP/MIME 签名 → 加密 → 封装 RFC 5322 → 发送。
组合形态为 RFC 3156 §6.1 层叠(先签后密),收件端 `gpg --decrypt` 与本库
`@mime.decrypt_mime` 均可打开。

## 端到端验收(推荐先跑)

```bash
./example/mailer/e2e.sh
```

四道门:① 真实 SMTP 线上发送(本地 mini-sink)→ ② gpg 解密 + 拆件验签
`Good signature` → ③ 正文/附件字节级比对 → ④ `--roundtrip` 自产自解。
零外部依赖(python3 标准库)。

## 库 API(src/mail 组装;传输在 example/netmail)

组装能力是可复用的库 API(不含传输):

```moonbit
let message = @mail.build_encrypted_mail(
  from, to,                       // MailAddress(display_name, addr)
  subject=..., text=...,          // 头值必须 ASCII(fail-fast)
  attachments=...,                // base64 CTE
  signer=private_key,             // 先签:multipart/signed(micalg=pgp-sha256)
  recipients=[public_key],        // 后密:multipart/encrypted
  domain="mailpgp.example",       // Message-ID / EHLO
  now_unix?, tz_offset_minutes?,  // 缺省取平台时钟/时区(native)
)
```

编码策略(RFC 3156 §3:签名数据必须 7-bit):正文纯 ASCII → 7bit,否则
quoted-printable;附件一律 base64。

协议与传输实现位于共享演示包 `example/netmail`(socket/SMTP/IMAP 客户端),定位是
演示与测试基建、不属于库 API——发布 API 中的邮件能力是 `src/mail`(组装)与
`src/mime`(解析验签)。本 example 是薄壳 CLI。

## 发送

```bash
# 文件模式(推荐给真实邮箱:TLS/重试/队列交给 MTA)
moon run example/mailer -- --from "A <a@x>" --to "B <b@y>" ... --mode file --out mail.eml
msmtp --read-envelope-from < mail.eml

# SMTP 模式(仅限本地/可信中继;无 TLS 是既定边界)
moon run example/mailer -- --from ... --to ... --body-file ... --sender-key ... \
  --recipient-cert ... --domain ... --mode smtp \
  --smtp-host 127.0.0.1 --smtp-port 2525 \
  [--smtp-user u --smtp-pass-env SMTP_PASS]
```

安全边界(如实声明):**不支持 TLS**(纯 MoonBit 实现 TLS 1.2/1.3 不在本项目
范围),SMTP 模式只应对 localhost 或可信内网中继;非本地主机 + AUTH 会被代码层
拒绝(凭据不得明文过公网)。口令只从环境变量读取,永不进 argv。SMTP 仅限
native 目标(wasm/js 无 TCP)。DNS 不解析,`--smtp-host` 用点分 IPv4
(localhost 例外)。附件/头值含非 ASCII 时 fail-fast(RFC 2047/2231 未实现)。
