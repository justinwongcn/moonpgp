# 安全修复轮方案 — 2026-11-12（待批准，未动任何代码）

审计对象 HEAD 08b424a（= origin/main）。本轮审计 32 条发现已全部经 JEV 实弹验证：
31 条首发 noul ≥ 0.90（中位 0.989），1 条（F1 数值链）按协议复议后 0.997。
判定阈值沿用既定口径：≥0.90 确认，0.70–0.90 复议，<0.70 不修。
JEV 请求/响应存档：`/tmp/jev20261112_r*_*.json`（32 发单题请求 + `jev20261112_f1_recheck_*.json`）。
审计报告全文见会话记录与记忆 `audit-round-2026-11-12-head`；本方案取代审计报告的"建议下一步"一节。

## 总原则

- 与上两轮一致：全部落私有函数/包内改动，公开 API（.mbti）零变动为验收基线；
  仅 D1/D2 两个用户决策点可能产生 .mbti 变动，见文末"需你拍板"。
- 每项修复配 ≥1 个失败模式差分测试；bzip2 探针以小数据白盒形式固化为回归测试。
- 严格性收紧项（B3）逐项对照 gpg 互通夹具，防止误伤合法输入。

## B1 崩溃与 DoS（P1/P2，JEV 0.997–0.997，第一批，立即修）

| # | 发现 | 修法 | 验收 |
|---|------|------|------|
| B1.1 | F1 bzip2 位读 Int32 溢出 SIGABRT（探针实锤） | `BzBits.pos` 迁 `Int64`；守卫 `pos + n <= data.length()*8` 全程 Int64 计算（`priv` 结构，触点集中在 bzip2.mbt） | 小数据白盒回归：pos=2147483644 + get64(48) 必抛 truncated；全量 compress 测试绿 |
| B1.2 | F19 毒 PKESK 私钥路径 DoS（Table 26 raise 不可恢复） | `decrypt_inner_with_key`（pubkey.mbt:344）与 `recover_pkesk_session`（sessionkey.mbt:209）对命中 PKESK 的解包 catch `Malformed` 后丢弃该 ESK 继续（§10.3.2.1 MUST discard），与密码路径对齐；末尾无匹配仍走原错误 | 差分：[毒 v3 PKESK + 合法 ESK + SEIPD v2] 私钥路径解开；仅版本不匹配消息干净报错；gpg 互通夹具绿 |
| B1.3 | F24 IMAP scan_parens 递归爆栈 | `scan_parens` 加 `depth` 参数（入口 0，递归 +1，`guard depth <= 50` 超限 malformed）；对齐 mime 侧 `max_mime_depth` 惯例 | 白盒：10 万 `(` 一行 → malformed 非 abort；imap 既有测试绿 |
| B1.4 | F20 导入同 UID last-wins O(N²) | `parse_transferable` 维护 `Map[String, Int32]`（uid → bindings 下标），认证覆盖与 CertificationRevocation 两分支共用；last-wins 语义不变 | 既有 key_codec 测试全绿 + last-wins/撤销附着正确性新测试（不设计时断言） |
| B1.5 | F25 netmail 读取无总量上限 | `LineBuffer::read_line/read_raw_line` 加单行字节上限（1 MiB，超限 raise）；`read_logical_line` 加累计字节上限（64 MiB）；imap/smtp `read_reply` 加行数上限（1 万 / 1000）；常量具名+注释 | 假流单测：超限 raise 非挂起；mailreader 冒烟路径不受影响 |

## B2 密钥材料与门禁对称性（P3，JEV 0.987–1.000，第二批）

| # | 发现 | 修法 | 验收 |
|---|------|------|------|
| B2.1 | F16 Debug 泄私钥材料 | `SecretKeyPacket`/`PrivateKey`/`SessionKey` 改手写 `to_repr`：`secret_material=<N octets>`、种子/会话钥以长度代原文；其余字段照常 | 新测试断言 Debug 输出不含密钥首字节；.mbti 零 diff |
| B2.2 | F13 签发侧可产 MD5 签名 | `make_document_signature_with`/`sign_cleartext_with` 入口拒 `Md5`（raise），SHA-1 保留（文档化 legacy 决策） | 测试：sign_cleartext_with(Md5) raise；SHA-1 签发保持可用 |
| B2.3 | F18 RSA e 无校验（e=1 平凡伪造） | 导入单点校验：`rsa_public_parts`（key_signing.mbt:637）加 `guard e >= 3 && e 为奇 && e < n`，from_armored/from_bytes 全覆盖 | e=1/偶数 e 导入 raise；gpg 互通夹具（e=65537）全绿 |
| B2.4 | F10 charge_argon2 回绕旁路预算 | 单位计算迁 Int64，钳制后入账（`priv` 结构） | 边界测试：cap=2^24 时预算仍有效 |
| B2.5 | F11 budget 默认参数潜伏后门 | 删 `unwrap_one_skesk` 的 budget 默认值，改必填（私有函数，两调用点已显式传） | 编译期强制；现有测试绿 |
| B2.6 | F12 C3 门禁畸形嵌入签名 raise 破契约 | verify 侧 `subkey_cross_certified` 调用点（sign.mbt:524）catch → `Failed`；签发侧保持 raise（fail-closed，文档注明） | 毒嵌入签名导入后 verify_* 返回 Failed 非 raise |
| B2.7 | F14 decrypt_and_verify 与 builder 语义不一致 | 密钥循环补 per-key catch + last_error，语义对齐 builder | 差分：两入口对"首把失败次把可解"行为一致 |
| B2.8 | F15 KeyRing now=0 静默跳时间门禁 | **已拍板选 B**：`now` 改必填（删 `= 0L` 默认）；仓库内调用点显式传 `unix_now()`；docstring 说明非原生目标显式传 0 的语义 | 编译期强制；.mbti 按实际 diff 评审；随 0.5.0 发布 |
| B2.9 | F17 解锁态导出零提示 | **已拍板选 B**：`to_armored`/`to_bytes` 加 `allow_unlocked~ : Bool = false`，解锁态默认 raise | 源码兼容、行为破坏；CHANGELOG 突出；.mbti 按实际 diff 评审 |

## B3 解析严格性与写侧（P3，JEV 0.915–0.998，第三批）

| # | 发现 | 修法 | 验收 |
|---|------|------|------|
| B3.1 | F2 zlib cap 加法回绕 | 改判 `produced > max_out - out.length()`（前置 `out.length() <= max_out` 不变式，减法不回绕） | 单测边界；既有测试绿 |
| B3.2 | F3 derive_hash_key 无上限 | 入口 `guard key_len >= 0 && key_len <= 255`（S2K 派生约定上限） | 直构大 key_len raise；wire 路径不受影响 |
| B3.3 | F4 子包长度 224–254 宽容 | `guard first < 224 || first == 255` 超限 malformed（对齐 RFC §5.2.3.1 与包级解析） | 单测三型长度 + 224-254 拒收；gpg 互通夹具绿 |
| B3.4 | F5 Issuer 子包长度不校验 | `validate_hashed_subpackets` 增 Issuer Key ID（==8）与 Issuer Fingerprint（21/33）精确长度闸；unhashed 区同步（仅此两类，其余维持现状） | 畸形长度体拒收；互通夹具绿 |
| B3.5 | F6 RSA/legacy MPI 尾随字节 | RSA/EdDsaLegacy 签名参数与 RSA PKESK 读完加 `guard r.remaining() == 0`（对齐 Ed25519/X25519 严格侧） | 互通夹具绿（gpg 不产尾随字节）；附加垃圾字节的包拒收 |
| B3.6 | F7 armor 三处读侧不对称 | END 行整行匹配 `armor_type.end_marker()`；`parse_crc_line` 解码带 `ignore_whitespace=true`；去掉 `!body.is_empty()` 条件（空载荷 CRC 行正常识别） | 新单测三例；armor/互通 armor 夹具全绿 |
| B3.7 | F8 写侧静默截断 | 四处加 guard：serialize Unknown tag 拒收（本库从不序列化 Unknown）；PKESK `encrypted.length() <= 255`；v6 秘钥参数长 ≤255；v4 签名 hashed/unhashed ≤65535 | 直构越界 raise；.mbti 零 diff |
| B3.8 | F9 to_body 直构越界 | `params.length() >= N` guard（EdDsaLegacy 2 / Ecdh 3） | 直构缺参 raise 非崩 |

## B4 mail/mime/example（P3，JEV 0.956–1.000，第四批）

| # | 发现 | 修法 | 验收 |
|---|------|------|------|
| B4.1 | F21 RFC2047 解码无 CTL 过滤 | `decode_rfc2047` 输出过滤 C0（保留 \t），对齐编码侧门禁 | 编码词含 ESC/CR 的解码输出已剥离；既有 rfc2047 测试绿 |
| B4.2 | F22 sanitize_filename 索引错位 | 最后分隔符改按 UTF-16 code unit 扫描（与切片同空间），并拒绝 base 前导 `/`、`\` | 单测：emoji 前置文件名三例；既有 mailreader 测试绿 |
| B4.3 | F23 折叠头 O(n²) | `header_value` 改 StringBuilder（对齐 `parse_folded_headers`） | 既有测试绿；大折叠头不再平方 |
| B4.4 | F26 UIDVALIDITY 不跨会话 | **已拍板选 B（最小实现）**：mailreader 状态文件持久化 folder→UIDVALIDITY，`--fetch` 时不一致硬拒并提示删除状态文件重置；`--last`/`--fetch` 输出 UIDVALIDITY | 错信场景硬拒单测；README 落地 |
| B4.5 | F27 literal 100MB 偏宽 | `max_literal` 降 4 MiB；`ImapClient` 加会话累计预算（512 MiB）具名常量 | 超限 raise 单测；mailreader 冒烟绿 |
| B4.6 | F28 String 版 MIME API 弱于字节版 | `content_type_boundary`/`split_multipart` 就地重写为字节版等价严格逻辑（首次实现在**参数位**找 boundary=、quoted-pair 感知、关闭定界 padding 校验）；签名不变 | 单测：note= 劫持例、`--B--evil` 例；.mbti 零 diff |
| B4.7 | F29 PGP/MIME 行尾空白覆盖缺口 | **已拍板选 B**：交付规范化正文（验证面=交付面），docstring 同步；gpg/gopenpgp 互通夹具复测纳入验收 | 互通夹具绿；行为变更走 CHANGELOG |
| B4.8 | F30 SELECT folder 无校验 | `imap_select` 入口复用 `validate_login_arg(folder, "folder")` | CRLF/引号 folder raise 单测 |
| B4.9 | F31 SMTP 信封校验层级 | `smtp_session` 入口对 from/recipients 本地校验（可打印 ASCII、拒 CRLF/CTL，与 validate_addr_spec 等价），netmail 自含不依赖 @mail | 注入地址 raise 单测；mailer 冒烟绿 |
| B4.10 | F32 reply_code 第 4 字符 | `reply_code` 要求第 4 字符为 `' '`/`'-'`/CR/行尾（RFC 5321 §4.2） | "2500 foo" 拒收单测；既有 smtp 测试绿 |

## 执行顺序与提交切分

1. **B1**（半天）→ 单提交 `安全:B1 崩溃与 DoS 修复`
2. **B2**（半天）→ 单提交 `安全:B2 密钥材料与门禁对称性`（文档修正按惯例 amend 进对应提交）
3. **B3**（半天）→ 单提交 `健壮性:B3 解析严格性`
4. **B4**（半天）→ 单提交 `健壮性:B4 mail/mime/netmail`
5. 每批完成即跑全量门禁；全部完成后统一复跑验收探针。

## 全轮验收标准

- `moon test` 三靶（native/wasm/js）全绿；新增失败模式测试 ≥ 15 个
- `moon fmt --check`、`moon check --target all --deny-warn` 过
- `.mbti` 预期 diff：仅 B2.8（`now` 改必填）与 B2.9（`allow_unlocked~` 参数）两处，按实际 diff 评审；其余各项零 diff（B5.3 的 `bits` 本为必填，无 .mbti 变动）
- 版本口径：B2.8/B2.9 为源码/行为破坏性变更，随下个 minor 版本（0.5.0）发布，CHANGELOG 迁移说明同步
- `interop/` gpg 互通夹具全绿（B3 严格性收紧的重点回归面）
- `scripts/ci_smoke.sh` PASS；B1 各验收探针复跑通过
- README 中英 + CHANGELOG [Unreleased] 同步（按惯例随代码提交）

## B5 续审补充（2026-11-12 晚，cipher/primitives/pki 逐行闭环，JEV 0.995–1.000）

上轮唯一覆盖缺口（crypto 核心 agent quota 失败，只做热点扫）本轮逐行收口：
cipher/ 8 文件 + primitives/ 11 文件 + pki/ 5 文件（~5100 行非测试源码）全部读完。
逐行区核查清白：CFB 双变体与 resync、SEIPD v1/v2、AEAD 帧边界、RFC 3394 KW、
GCM/EAX/OCB 全模式（对 RFC 7253/SP 800-38D/4493 逐式核对）、Argon2（GB/BlaMka/
index_alpha/H'/H0）、BLAKE2b、HKDF、HMAC、CAST5（RFC 2144 逐方程）、3DES、
bigint（ext_gcd/MR/无偏采样）、curve25519（RFC 8032 公式与恢复、RFC 7748 阶梯）、
x25519（clamp/低阶点拒绝/KDF）、RSA（CRT/Garner/PKCS#1 双向/质数生成）、ed25519
（sign/verify/cofactored）。非常量时间域运算/RSA 无盲化为既有文档化取舍（README
replacement seam），非新发现。

| # | 发现 | 修法 | 验收 |
|---|------|------|------|
| B5.1 | L1 `aes_key_unwrap` IV 检查逐字节早退比较（keywrap.mbt:137-141），与库内 ct_equal 约定不一致（JEV 0.995） | 改 `ct_equal(a.exact_view(), kw_iv 常量)` 一行；kw_iv 转 Bytes 常量 | 现有 KW 测试绿；新增正/负例各一 |
| B5.2 | O2 tag-20 层最终 tag 下非空明文静默忽略，与 seipd_v2_open 的空明文 guard 不一致（aead.mbt:282-291，JEV 1.000） | `aead_open` 最终 tag 处补与 seipd_v2_open 同款 `guard opened.length() == 0` | gpg/gopenpgp tag-20 互通夹具绿（其最终块恒空）|
| B5.3 | O1 `generate_rsa_key` 接受 2048 起，与自述引用的 RFC 9580 §12.4 "MUST NOT generate below 3072" 口径不符（rsa.mbt:200-207，JEV 0.999） | **默认文档化修法**：改注释如实声明"2048 为本库显式 opt-in 下限，偏离 RFC 3072 生成口径"+README 安全节注明；**或**（可选项）`guard bits >= 3072`（bits 本为必填，无 .mbti 变动；ci_smoke/示例需改 3072，keygen 变慢需实测） | 与所选口径一致；文档落地 |

## 决策结果（2026-11-12 用户拍板）

**政策：项目处于早期阶段，破坏性更新的成本相对收益更低——除非改动过大，否则优先安全。** 据此逐项落定：

1. **B2.8 → 选 B**：`now` 改必填（删 `= 0L` 默认）。安全强选项且改动小（删默认值 + 修仓库内调用点），编译期根除静默半开门禁。
2. **B2.9 → 选 B**：加 `allow_unlocked~ : Bool = false`，解锁态导出默认拒绝，与 lock/unlock 状态机同级；行为变更走 CHANGELOG。
3. **B4.4 → 选 B（最小实现）**：mailreader 持久化 folder→UIDVALIDITY 到状态文件，`--fetch` 时不一致硬拒并提示删除状态文件重置；`--last` 输出 UIDVALIDITY 保留。复杂度约 50 行，不构成"改动过大"。
4. **B4.7 → 选 B**：交付规范化正文（验证面=交付面）；gpg/gopenpgp 互通夹具复测纳入该批验收。
5. **→ A**：plan 随修复入库（与上轮先例一致；此项与破坏性更新政策无关）。
6. **B5.3 → 选 B（带应急口径）**：`guard bits >= 3072`，ci_smoke/示例/README 改 3072；开工时实测 3072 位 keygen 耗时，若分钟级拖垮 CI 门禁则退 A，实测数字写入注释与 README（退路执行时呈证据确认）。

以下为各决策点的分析记录（选项×优点×劣势），供回溯。

### 1. B2.8（F15）KeyRing `now` 默认 0L——过期门禁在省略时静默失效

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A（推荐）** 维持 `now~ = 0L` + docstring 硬警告 + 仓库内全部调用点显式传 `unix_now()` | .mbti 零 diff，0.4.x 可直接发；现有调用方零改动；不受 MoonBit 默认参数不能调用 raise 函数的语言限制（时钟调用会 raise，写不进默认值） | 外部调用方漏传 `now` 依旧静默得到"过期半开"——错误仍靠文档事后提醒，正是单侧门禁盲区的温床 |
| **B** 改必填（删默认值） | 编译期强制，漏传即编译错，静默降级从根上消除；与 `seal_to_recipients` 的显式时钟完全对称 | 破坏性源码变更（0.5.0 语义版本）；所有调用方（含下游）必须改；快速查询需自取时间 |

推荐理由：A 与"公开 API 零变动"验收基线一致，成本最低；B 留给下一个含破坏性预算的版本。

### 2. B2.9（F17）解锁态私钥导出零提示

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A** 仅文档警示（docstring + README） | 零 API 变动、零行为变化；导出明文私钥是合法需求（备份/迁移，gpg 同有 `--export-secret-keys`），不挡路 | 误用防护为零：解锁态调用 `to_armored` 落盘即明文，与 lock/unlock 门禁的重防护形成落差，仍依赖调用方读文档 |
| **B（推荐）** 加 `allow_unlocked~ : Bool = false` | 误用防护进类型系统：默认拒绝导出解锁态密钥，与 lock/unlock 状态机同等严格 | **源码兼容但行为破坏**（既有调用 `to_armored()` 仍可编译，但解锁态下改为 raise——行为变更需 CHANGELOG 突出）；.mbti 变动；备份/迁移流程须显式 opt-in |

推荐理由：本项目 lock/unlock 门禁一贯做得很重，B 是同风格补齐；介意 0.4.x 行为变更则退 A。

### 3. B4.4（F26）UIDVALIDITY 不跨会话比对

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A（推荐）** `--last`/`--fetch` 输出 UIDVALIDITY + README 警示"列表与取信同会话" | 零状态、零新协议面，几分钟落地；用户可自行对照；符合 example 的定位 | 靠人眼比对，实际会忘；防线是流程自觉而非机制 |
| **B** 持久化比对（状态文件记 folder→uidvalidity，`--fetch` 时不一致即硬拒） | 静默错信问题真正闭环：邮箱重建后 UID 语义漂移被机制拦截，与 IMAP 正确用法对齐 | 引入磁盘状态（路径/清理/多机不同步/损坏兜底等新问题）；example 复杂度明显上升；属于给示例程序造状态管理的越界复杂度 |

推荐理由：mailreader 是示例程序，A 与定位相称；若它要升级为长期真实客户端再做 B。

### 4. B4.7（F29）multipart/signed 行尾空白覆盖缺口

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A** 文档明示缺口（docstring + README） | 零行为变化、零互通风险；不扰动已实测的 gpg 2.4.5 尾空白剥离 deliberate deviation | 完整性缺口留存：中间人改行尾空白验证仍 Ok；"交付面≠签名面"只有读文档的人知道 |
| **B（推荐，若安全完备优先）** 交付规范化正文 | 验证面=交付面，缺口闭合；语义上"所见即所签" | 交付与传输原文有差异（尾空白被剥），归档/法务类消费方可能要求字节级原文；需 gpg/gopenpgp 互通复测确认夹具不破；行为变更需 CHANGELOG 突出 |

推荐理由：这是六项中唯一真正的完整性缺口，按本项目安全优先的惯例倾向 B；但 A 的互通零风险是实打实的——按你的使用场景（是否有人拿字节级原文）拍板。

### 5. 本方案文件是否随修复入库

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A（推荐）** 入库（随修复提交，上轮先例 f4e3f66） | 审计→方案→修复证据链在仓库可溯，评委/验收口径可复查；对 osc2026 是安全流程的展示面 | 公开仓库留存修复前缺陷细节清单（修复后即过时的"攻击者地图"）；根目录多一份维护中的 plan |
| **B** 不入库（留本地） | 不向公开面新增缺陷细节；根目录干净 | 证据链只在会话记忆，仓库不可溯；与上轮先例不一致（注意：上轮 plan 已在历史中，本项只决定新文件） |

### 6. B5.3（O1）RSA 生成下限 2048 vs 自述 RFC 3072 口径

`bits` 本就是必填显式参数，两个选项都**无 .mbti 变动**，差别纯在行为与文档。

| 选项 | 优点 | 劣势 |
|---|---|---|
| **A** 保持 2048 + 注释/README 如实声明"2048 为显式 opt-in 偏离 RFC 3072 生成口径" | 零行为变化；CI 冒烟 2048 保持快速（本实现 RSA keygen 为纯 bigint，3072 显著慢）；与 README/SECURITY 现有 2048 口径一致 | 与 RFC 9580 §12.4 自引口径持续偏离（诚实但未修复）；2048 新密钥安全裕度逐年下降 |
| **B（推荐）** 生成下限提到 3072（`guard bits >= 3072`） | 默认行为对齐 RFC，安全姿态增强；密钥导入面不受影响 | ci_smoke/示例/README 示例需改 3072；keygen 变慢（CI 时长上升，需实测 3072 位在本实现的生成耗时再定是否影响门禁） |

推荐理由：B 修复的是"代码与自己引用的规范不符"这一致性缺陷；若 3072 keygen 实测过慢拖垮 CI 门禁，退 A 并把实测数字写进注释。
