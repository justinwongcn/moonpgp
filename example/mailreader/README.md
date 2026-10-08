# example/mailreader — 取回并解密验证 PGP 邮件(IMAP 收信)

与 `example/mailer`(发送)对称的收信端:登录 IMAP 邮箱 → 列出最近邮件 →
按 UID 取回全文 → 交 `@mime.decrypt_mime` 解密 + MIME 解析 + 验签
(gopenpgp 四态:Ok / NotSigned / NoVerifier / Failed)→ 输出正文并落盘附件。

实现范围见 `docs/mail-fetch-plan.md`(v1.1):IMAP4rev1 六命令子集
(LOGIN / ID / SELECT / FETCH / UID FETCH / LOGOUT),仅 INBOX,无 STARTTLS。
协议客户端位于共享演示包 `example/netmail`,定位是演示与测试基建、不属于库 API
(发布 API 中的邮件能力是 `src/mime` 解析验签 + `src/mail` 组装)。本 example 是
薄壳 CLI。

## 端到端闭环(推荐先跑)

```bash
./example/mailreader/e2e.sh               # 默认:IMAP 明文 143 + --allow-insecure
E2E_TUNNEL=1 ./example/mailreader/e2e.sh  # 隧道:本地 stunnel → IMAPS 993
```

脚本先用 `example/mailer` 给自己发一封新的签名+加密邮件(msmtp 经 TLS 提交),
再用 mailreader 列信、按 UID 取回、解密验签——发送端与接收端在一条命令里互证。
前置:`msmtp`、`~/.pgp-demo/` 下的密钥与凭据(见脚本头部的环境变量,均可覆盖)。

### 双账号闭环(163 ↔ ProtonMail)

```bash
./example/mailreader/e2e_two_account.sh
```

用两把真实账号私钥跑三道门,全部经真实 SMTP/IMAP 与真实邮箱:

1. **A→B 发送**:A(163)私钥签名 → B(ProtonMail)公钥加密 → `smtp.163.com:465`
   提交;断言产出的 PKESK 指向 B 的 cv25519 子钥(`EE1F3A43F048437A`)。
2. **A→A 闭环**:A 签名+加密给自己 → 提交 → IMAPS 取回 → A 解密验签
   (`decrypt+verify OK`)。
3. **B→A 真实互通**:取回 ProtonMail 自己产生、留在 INBOX 的回信,用 A 解密、
   用 B 公钥验签。

B 的私钥是 S2K 锁定的,本脚本只用其**公钥**部分(加密 + 验签),从不解锁;
A 的私钥无口令。凭据同样只从 `$CREDS_FILE` 读,密钥路径全部可用环境变量覆盖。

## 命令行

```bash
# 列出最近 5 封(UID 用于后续按信取回——序号跨会话会因删信平移)
IMAP_PASS=$(cat ~/.pgp-demo/smtp-pass) moon run example/mailreader -- \
  --imap-host 127.0.0.1 --imap-port 1143 \
  --user me@example.com --pass-env IMAP_PASS --last 5

# 按 UID 取回 + 解密 + 验签(附件落盘到 --out)
... --fetch 1730062003 \
    --keys my-private-key.asc --certs senders-public-key.asc \
    --out ~/fetched
```

## 明文与 TLS(与发送侧同一条安全边界)

纯 MoonBit 不实现 TLS(见 README.mbt.md 安全声明),因此:

- **推荐真实路径:stunnel → IMAPS 993**(TLS 由外部工具承担,与发送侧
  msmtp 手-off 同构)。6 行配置:

  ```
  client = yes
  [imaps]
  accept  = 127.0.0.1:1143
  connect = imap.example.com:993
  verifyChain = yes
  CAfile  = /opt/homebrew/etc/openssl@3/cert.pem
  checkHost = imap.example.com
  ```

- **明文直连 143 属显式 opt-in**:非 localhost 的主机必须传
  `--allow-insecure`,否则连接前直接拒绝(凭据不得默认明文过公网)。
  注意:邮件内容本身是端到端加密的,明文端口暴露的是**凭据与元数据**,
  不是信件内容。

- 口令/授权码只从环境变量(`--pass-env`)读取,永不进 argv。

## 已知边界(v1 裁剪项,如实声明)

- 仅 INBOX(其它文件夹需 RFC 3501 UTF-7 邮箱名解码);
- 不支持 IDLE/推送、CONDSTORE/QRESYNC、APPEND;
- `--imap-host` 不解析 DNS,需点分 IPv4(localhost / 127.0.0.1 例外;域名请交给
  stunnel 或在脚本里先解析);
- LOGIN 参数限可打印 ASCII(禁 `"` `\` `{` 与控制字符);
- 收到非 PGP 邮件时照常交付正文,验签状态为 NotSigned/NoVerifier(四态语义)。
