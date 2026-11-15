# 黑客轮审计与修复 — 2026-11-13(凌晨,已随修复提交入库)

审计对象 HEAD 1147498(= B4+B5 收口后的本地 main)。做法:三个红队 agent 并行
通读 08b424a..HEAD 修复 diff 本身(修复代码此前从未被审)+ 主 agent 补查上游
flate、cmd/、interop、MD5 漏斗、0L 时钟残留。全部 22 条候选发现先写探针
(断言期望行为,红=实锤),再逐条 JEV noul 单题验证(阈值 ≥0.90 确认 /
0.70–0.90 复议 / <0.70 不修)。JEV 请求/响应存档 `/tmp/jev_round_20261113/`
(j1–j15 首发 + j*r* 复议 + 第二轮 e*/fr1*,597–880 字节/发)。

## 确认并修复(14 项)

| # | 发现 | JEV | 修复 |
|---|------|-----|------|
| j1 | decode_rfc2047 裸文本直写输出 + C1/DEL 穿透字节过滤(探针:ESC/BEL/U+009B/DEL 存活) | 0.971(复议) | 输出边界统一 `strip_ctl_string`(C0+C1+DEL,tab 保留),encode 侧 require_no_ctl 同步 C1 带 |
| j2 | String 版 split_multipart 与字节版漂移:尾随空白定界行拒绝、缺尾定界符丢件(探针+字节版对照) | 0.613→0.72(复议仍<0.90,**带异议执行**:探针差分实锤 + F28 自述收敛目标) | `line_is_delim_ws` 运输空白容忍 + EOF flush 尾件,F28 测试期望更新 |
| j3 | armor END 行尾随空白硬失败(F7 修复引入回归,BEGIN 同形状通过) | 0.976(复议) | END 改用 `line_is_marker`(整行等价,兼容运输空白,垃圾仍拒) |
| j4 | s2k:Iterated/Argon2 key_len 无闸(百万字节派生实锤)+ validate_argon2 放行负 passes + 负 cap 投毒预算 | 0.982(复议) | derive_key_capped 漏斗闸 key_len 0..255;passes/parallelism ≥1;四个 pub 入口 guard cap ≥1;charge_argon2 永不减计 |
| j5 | X25519/ECDH PKESK 不精确消费(RSA 独严,注释自称对齐) | 0.950(复议) | 两分支补 `remaining()==0` 闸 |
| j6 | unhashed 区 Issuer 无长度闸(7 字节 issuer 原样返回) | 0.908 | `validate_issuer_subpackets` 应用到 unhashed;issuer_key_id 直构防御闸 |
| j7 | serialize_packet_old 接受 Unknown(70)→截断误标 tag 6 | 0.997(复议) | 补 Unknown 闸;签名 `Bytes`→`Bytes raise`(.mbti 预期 diff) |
| j8 | mailreader 无名头行 "junkreal" 值污染(F23 回归) | 0.989 | 非头行(无冒号/空名)整行跳过,flush 移入头起始分支 |
| j9 | ehlo_domain 无校验(CRLF 注入实锤)+ AsyncSock::read_line 无行上限(TLS 路径) | 0.974 | EHLO 复用信封校验;AsyncSock 移植 MAX_LINE_BYTES |
| j10 | FETCH literal 4MiB 截断合法全文抓取(BODY.PEEK[] 一件就是全文) | 0.904 | 单 literal 上限 4MiB→64MiB,会话 512MiB 预算不变 |
| j11 | pki 三个私钥载体 Debug 全量打印 d/p/q/u/seed/scalar(F16 残留) | 0.981 | 三类型手写 to_repr(仅长度),去 derive(Debug) |
| j12 | NotSigned 邮件交付正文也被无条件规范化(F29 范围过宽) | 0.989 | 仅 `verifiable`(根 multipart/signed)交付规范化;未签名交付原样;嵌入式签名=覆盖整个 literal,子件交付原样(gpg 夹具期望回退) |
| j13 | decrypt_and_verify 错误 to_string 抹平变体+文本攻击者可控;负 cap 投毒(与 j4 合并修) | 0.896/0.881(复议;<0.90,但负 cap 部分被 j4 的 0.982 陈述显式覆盖;变体保留按同批执行) | 保存错误值 `raise e` 重抛保留变体;cap guard 见 j4 |
| j14 | UIDVALIDITY 响应码位置硬编码+≥2^31 解析失败按 0 比对(合法会话误硬拒);状态文件 `\|` 键碰撞 | 0.979 | 括号码内 token 扫描;`parse_int64`+uidvalidity 迁 Int64(.mbti 预期 diff);状态文件键 percent-encode |

## 不修(协议判退)

- j15 `SecretKeyPacket::to_body` v6 毒形状 round-trip 不对称:首发 0.748,复议 **0.228** —— 仅直构面,parse 必拒,无 wire 路径。登记备查。
- C10 zlib NeedMoreOutput+0 死转疑虑:核对 @zlib 契约(coverage_test 钉死 blocked 步消费输入或产出),32KiB chunk 恒有空间,不可达。
- 遗留(上轮 #5)interop/tmp_ct_test.mbt 本轮未动(避免无关 diff)。

## 测试与门禁

- 探针全部转正为回归测试:mail/rfc2047_probe_test.mbt、mime/mime_probe_test.mbt、
  armor/armor_probe_test.mbt、s2k/{s2k_probe_test,hackround_wbtest}.mbt、
  packet/hackround_wbtest.mbt、pki/hackround_wbtest.mbt、
  example/{mailreader,netmail}/hackround_wbtest.mbt。
- 附带:rfc2047 空转 CR/LF 用例换真载荷(B11)、F17 三态测试补 locked-无-flag
  断言(A6)、pki 测试名 2048→3072 对齐(C9)。
- 门禁:`moon test` native **594/594**;`moon fmt`/`moon check --deny-warn` 过;
  wasm/js 见提交前复跑;`.mbti` diff 恰为预期四处(j7 签名、j11 Debug impl、
  j14 Int64+parse_int64)。
- 上游 flate 核查(上轮遗留任务 #1)本轮闭环:fill() 的 bit_count 上界 n+7≤24
  (Huffman ≤15/字段 ≤16),bitbuf 第 31 位永不置位,Int32 算术移位无符号扩展
  风险;wpos 受本库 512MiB cap 包络约束,依赖内不可达。遗留任务 #1 关闭。

## 第二轮(晨间组合审计,08:08–08:55)

两个 agent:复审本轮修复 diff 自身 + 跨层组合审计。四项确认并已修复
(JEV: e1 0.998 / e4 0.907 确认;e2 0.674、fr1 0.795 带异议执行——均为探针/
对照差分实锤且符合既有收敛目标):

- **E1(高危)混合锁态导出闸绕过**:is_locked 的 any-component 语义使
  "主钥明文+子钥加锁"证书通过 F17 闸,主钥明文私钥默认落盘。修复=导出闸
  改 is_fully_locked(全组件合取),探针 round2_wbtest.mbt 拼包构造混合证书
  钉死(注:探针构造迭代期间修复已落,pre-fix 红未及捕获;代码路径实锤
  + JEV 0.998)。
- **E2** mailreader 列表行兄弟字段(date/flags)裸打印——新增
  `@mail.sanitize_terminal` pub 助手套同一 C0/C1/DEL 过滤(.mbti +1 fn)。
- **E4** verify_pgp_mime_signed 与 decrypt_mime 规范化器互不相认(同邮件
  一 Ok 一 Failed)——extract_pgp_signed 收敛到 mime_canonicalize。
- **F-R1**(修复自审)split_multipart epilogue 复活——补 finished 停止
  标志对齐字节版 walk.mbt。

登记不修(时间盒 + 影响面):E3 decrypt_mime 全文首块 armor 扫描可被前置
诱饵块顶替(状态诚实上报,交付面混淆);E5 verify_cleartext CRLF 头段
硬拒(Windows gpg clearsign 互操作);E6 mailreader D2 注释承诺 NotSigned
非零退出未兑现;E7 密码路径把 v4 SKESK MDC 篡改报成 WrongPassphrase;
E8 UIDVALIDITY 状态文件 TOCTOU;F-R3 j10 放大 rfc2047 既有 O(n²)(问题
先于本轮存在,Subject 单行 ≤1MiB 时仍可达 ~10^11 字符操作)。

遗留任务 5(interop/tmp_ct_test.mbt)已删除,interop 42/42。

## 清理轮(2026-11-13 午后,用户令:清理掉所有发现的问题)

登记清单逐项闭环(全部先探针后修,JEV 单题验证):

- **j15**(用户拍板覆盖 JEV 0.228 判退):to_body 补齐 parse 的 v6 拒收
  (usage 255 + legacy cipher-id),探针 packet/hackround_wbtest 追加。
- **E5**(JEV 0.349 但探针实锤——修复 stash 后捕获 pre-fix 红
  `illegal armor header`):verify_cleartext 入口归一 CRLF,LF/CRLF 变体
  验证结果字节相等。
- **E6**(JEV 0.989):mailreader 抽出 delivery_failure 单闸门函数,
  NotSigned/NoVerifier 不再静默 exit 0。
- **E3**(JEV 0.984):decrypt_mime MIME 结构感知取载荷(深度优先找
  PGP MESSAGE 标记叶子),诱饵装甲块不再顶替;bare armored 走回退扫描。
- **N1**(新发现,清理 E3 时暴露):无 MIME 头的裸载荷被当头解析、
  正文交付空串——旧测试原把空交付钉为预期;改为按 text/plain 包裹交付
  (gopenpgp 对非 MIME 明文同语义)。
- **F-R3**(JEV 0.179 但实测挂死 20+ 分钟):try_parse_encoded_word 从
  每个 opener 无界重扫剩余全文 → 平方;600KB 对抗输入修复前挂起、修复后
  ~1ms。修=扫描窗封顶 99 字符(RFC 2047 §2 词长 ≤75)+失败起点跳 2
  (无损:'?' 不能开词);跳过的 '?' 仍进 raw 透传(unsupported charset
  用例钉死)。
- **E7**:密码路径把 v4 SKESK 的 MDC 失败归类 WrongPassphrase 是格式
  固有(v4 SKESK 无自身完整性,误判会破坏重试语义)——改为代码内精确
  注释,非代码缺陷。
- **E8**:状态文件原子写不可达——moonbitlang/x/fs 无 rename API;撕裂
  文件行为本就 fail-closed(硬拒),登记为依赖能力缺口。

仍留档非代码项:上轮遗留 #2(PGP/MIME 二进制附件行尾残余,需上游签名层
raw+canonical 双交付回调设计)/#3(UIDVALIDITY 多机同步,产品级)/#4
(3072 keygen 性能,优化项)/A1(packet 层 pub(all) 字段的设计边界,
用户政策:改动过大则文档化)。

门禁:native 600/600、mime 99/99、fmt+deny-warn 过、wasm/js 见提交、
ci_smoke 复跑。变更零 .mbti diff(本轮全部私有函数/包内改动)。
