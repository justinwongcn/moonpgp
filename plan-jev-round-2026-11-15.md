# JEV 循环第 1 轮（2026-11-15 13:39 起）

目标流程：扫描 → 修复 → 验证 → 文档 → 提交，循环至「连续 2 轮无新 bug」或
2026-11-16 09:00。JEV 请求/响应存档 `/tmp/jev_goal_20261115/`。

## 扫描

三个 agent 分面（并发上限连续撞限，按 5 分钟退避串行重试后全部回报）：

- A：cipher/ + primitives/ + s2k/ + compress/ + error/（既往缺口分面）→ 2 条
- B：api/ + cmd/ + agent/ + 顶层 + example/netmail → 9 条
- C：pki/ + packet 写侧 + armor/ + interop/ + reference/ → 7 条（AR-1 与本轮
  自查 R1 重合，合并处置）

主循环自查（agent 分面之外）：mail/ + mime/ + example/mailreader + cmd/main → 2 条。
所有 17 条候选逐条 JEV noul 单题验证（一题一判，含 2 条复议：api3 0.884→0.990、
pk4 0.802→0.994），全部 ≥0.99 或经复议确认。

## 确认并修复（17 项）

| id | 缺陷 | JEV | 修复 |
|----|------|-----|------|
| M1 | mailreader `--resync` 布尔旗标吞下一参数（文档组合 `--resync --fetch 42` 报 unknown flag；`--resync --out` 静默丢 --out） | 0.998 | parse_args 布尔旗标特判 |
| Q1 | mail/build 7bit 分支不查行长（RFC 2045 §2.10 的 998 上限；严格 MTA 500/552） | 0.997 | is_ascii_text 加 MAX_7BIT_LINE |
| A1 | argon2 `8*parallelism` Int32 回绕绕过最小内存防护 → 零长 mem → SIGABRT（p≥2^28 探针实锤杀进程） | 0.996 | wire 对齐 cap：passes/parallelism ≤255（F3 先例） |
| A2 | argon2 passes 无上限 → 直构 2^30 挂死 | 0.960 | 同上（红态=数小时挂起，修后断言） |
| M2 | cmd basename 字符计数 vs UTF-16 切片漂移（F22 的 cmd 孪生实例） | 0.986 | code-unit 扫描（F22 模式） |
| M3 | parse_bits 乱码静默回退 3072（违反 m5 大声失败约定）+ generate_rsa_key 无上限 | 0.992 | parse_bits raise + RSA ≤16384（OpenSSH cap） |
| R1 | armor encode headers 无校验 → CR/LF 注入伪行（mail 侧 require_ascii 的 armor 孪生缺口） | 0.993 | require_armor_header；encode 签名改 raise（.mbti 变更） |
| pk1 | serialize_packet_old 已知 tag≥16 翻成新格式另一 tag（17→4，F8 的同算术残余） | 0.988 | 老格式 tag 域 4 bits 闸 |
| pk2 | extract_literal 逐包重序列化 → parse 接受的 Unknown(保留号) 包使整条解密硬失败（gpg 跳过继续） | 0.988 | 包列表直通重构 + Unknown 跳过（探针双红） |
| pk3 | PublicKeyPacket::parse 无尾随消费闸 → import 接受垃圾字节、to_body 丢字节、v4 指纹漂移 | 0.983 | r.remaining()==0 闸（F6 parity） |
| pk4 | v6 签名/OPS to_body 不复检 salt 尺寸/指纹宽度 → 直构面写的自家 parse 拒收 | 复议 0.994 | salt_size_of_hash 对照 + v6 指纹 32-octet 闸（SIG/OPS） |
| pk5 | literal 'l'（RFC 9580 LF-text）wire→wire 往返改写 0x6C→0x62（'t'→'u' 有登记，'l' 没有） | 0.994 | 'l' 注册为独立格式 + to_body 写回 0x6C |
| net1 | imap_fetch_recent last_n≤0 构造 FETCH 6:0 倒序非法段（docstring 声称的钳制不存在） | 0.959 | guard last_n≥1（探针桩驱动） |
| cmd1 | lock/unlock 原地截断重写唯一密钥文件，写中途失败=钥毁 | 0.983 | temp 文件 + rename(2) 原子替换（native），非 native 保持原样 |
| ct1 | cleartext 签名对尾空白行自产自不可验；gpg 实机锚定规范形语义（只排除最后一个行尾分隔符，其前尾空行是内容；显示层从原文构建） | 0.962 | canonicalize_cleartext 重写 + dash_escape_display 从原文构建 + 3 个 gpg 夹具回归（testdata/gpg-cleartext-*） |
| api1 | 五处重试循环把类型化错误压成字符串（j13 只修了 sign.mbt 一处） | 0.995 | Error? 重抛（builder×3、pubkey、sessionkey） |
| api2 | EncryptionBuilder::finish 静默丢弃 password（recipients 分支）与 signer（密码分支），违反 docstring 组合承诺 | 0.995 | seal_esks_and_seipd 统一封装（PKESK+v4 SKESK 共享会话钥）+ signed/literal_inner_stream + v6 inner 封装；v6 recipients × v4 口令显式拒 |
| api3 | recover_session_key_with_key 对损坏 RSA PKESK 把 S04 掩码随机钥当成功返回 | 复议 0.990 | unwrap_pkesk_checked（恢复路径诚实失败；解密路径保持掩码） |
| api4 | from_armored 只导入拼接钥环第一块（gpg --import 语义），其余静默丢失 | 0.986 | decode_all 扫描 + 多钥块显式拒（Message/Signature 垃圾块仍容忍） |
| api5 | v4 SKESK 读侧长度闸只认无校验和形状；恢复路径 1/256 错误口令假成功 | 0.968 | **改判**：RFC 9580 §5.3.1 已删除 v4 SKESK 的 2-octet 校验和（明文 esk = 算法字节 + 会话钥），原写侧形状才合规——首版「补写校验和」修复被 gpg 实机探针否决（weird size for an encrypted session key (35)，提交前功能复验拦下）后回滚；最终处置=写侧保持 9580 形状，读侧兼容 4880 时代带校验和形状（校验和即 unwrap 时证明，错误口令 WrongPassphrase 前移），恢复路径假成功为无校验和形状的格式固有 |
| api7 | verify_detached 只验第一个 Signature 包 → gpg 双 -u 分离签名对第二把钥必假阴性 | 0.979 | 遍历全部签名包，Ok 胜出否则取最差 rank |

（表中 17 条 = agent 15 条去重 AR-1 后 14 条 + 自查 2 条 + A 分面 2 条 - 重复合并；
API 编号沿用 agent 报告。）

## 不修/改判（本轮）

- pk4 首轮 0.802 复议后 0.994 修复（非不修）。
- api6 孤立代理对：纯 MoonBit 无法构造（lexer 拒绝 + Int::to_char 校验），
  防护落在 utf8_bytes chokepoint 服务 js 宿主边界（JS 字符串可携带）；
  修复可测面=合法增补平面往返，孤立代理分支无语言内可运行探针（记录）。
- A 分面否决清单：aead chunk_size 转换不可达、bzip2 BWT/Huffman 界受防、
  zlib NeedMoreOutput 不可达、Argon2 index_alpha 代数验证等（详见 agent 报告存档）。

## 测试与门禁

- 探针转正：cmd/main_wbtest（新建）、mail/build_test、primitives/argon2_test、
  packet/packet_test、api/pk2_wbtest（新建）、api/hackround2_wbtest（新建）、
  example/netmail/imap_wbtest、example/mailreader/main_wbtest、armor/armor_test、
  interop/gopenpgp_test（gpg 夹具）、pki/pki_test。
- 红态证据：M1（unknown flag '42'）、Q1、M2（/file.txt）、M3、A1（SIGABRT
  杀原语测试进程）、pk1/pk3/pk5、pk2（双红：serialize 拒 + leading Unknown）、
  pk4（stash 双探针红）、net1、ct1 夹具（Failed≠Ok ×2 + 首 fix 规则被 gpg
  夹具否定后重写）、R1（encode 收下 CR/LF）、api4（stash 轮:拼接钥环静默导入）。
- 修后断言（红态不可安全运行）：A2（挂死）、M3 上限（挂死）。
- 红态不可重建（如实记录）：api1/api2/api3/api7——这四项的修复与跨文件签名网
  （armor encode→raise、utf8_bytes→raise、unwrap 四元组、builder 统一封装）
  交织,孤离 stash 任一文件即编译失败,全量回退又与未跟踪探针所依赖的新 API
  冲突;其机制均经代码逐行核实 + JEV 0.98–0.995 + 修后行为测试锁定。教训:
  跨文件重构前应先落红探针（本轮 pk1/pk2/pk3/pk5/net1/ct1 等均按此序）。
- .mbti 变更（预期）：armor encode→raise、pk 的 ecdh_anonymous_sender→raise、
  api/revocation 内部函数；pkg.generated.mbti diff 在提交中逐条核对。

## 遗留

- 无本轮新登记；既往登记（A1 packet pub(all) 0.5.0+、#2/#3/#4）不变。

## 第 2 轮(同日,修复 diff 复审 + 遗留候选)

diff 复审 agent 通读 15807e5 全量 diff,5 项发现(F1 高/F2-F3 中/F4-F5 低),
另把第 1 轮登记的「密码路径不验内嵌签名」升级为候选(pw-verify,JEV 0.997)。
全部处置:

| id | 发现 | JEV | 处置 |
|----|------|-----|------|
| pw-verify | DecryptionBuilder 口令分支忽略 verification_key:内嵌签名的口令消息返回 Data(与密钥路径分叉,调用方不可区分「无签名」与「有签名未验证」) | 0.997 | decrypt_password_and_verify(新):open_password_container(容器解密出原始内层流)+collect_data_sig+逐验签者取最优 rank;builder 口令分支接线(红探针 NotSigned≠Ok→绿) |
| F1 | .password_v6().recipient() 组合仍静默丢 v6 口令(recipients 分支不消费 passwords_v6)——api2 同类残留 | 0.626→**探针实锤**(v6 口令持有者解不开,探针推翻低分) | 显式拒(fail-closed);RFC 允许 v6 SKESK+v6 PKESK 共存,真支持登记后续 |
| F2 | api3 探针假阳性:corrupt[14] 翻的是 MPI 位长低字节,F6 尾随闸在 unwrap 前就拒包,修复前后同绿 | — | 探针改 corrupt[16](MPI 值内);红态经外科式单行回退(unwrap_pkesk_checked→unwrap_pkesk)捕获:掩码路径返回垃圾钥假成功(`false` is not true),恢复 checked 后绿 |
| F3 | cmd1 原子替换权限回归:temp 文件继承 umask 0644,rename 换 inode 后用户收紧的 0600 丢失(私钥本地泄露面);写中途失败残留 temp | 0.990 | temp 文件 chmod 0600(唯一调用者是 lock/unlock 私钥)+errdefer 清理(写失败/rename 失败均无残留);实机验证 lock 后 stat=600 |
| F4 | ct1 docstring 写的规范形字节与实现矛盾("text\r\n\r\n" 应为 "text\r\n");往返测试注释承诺断言但代码 `let _ = returned` | — | 注释改正;补真断言 canonicalize(returned)==canonicalize(text) |
| F5 | verify_detached 多包遍历:结构损坏的后续包以 Malformed 压掉先前包的确定性失败结论 | 0.991 | 逐包 parse+verify 收敛为 Failed rank,不逃逸异常 |

diff 复审同时确认其余修复干净(会话钥长度三处对齐、esk 双形状无混淆、ct1
边界自洽、extract_literal 重构等价、argon2 caps 与 KAT 兼容、from_armored
诱饵无误伤、api7 best 语义正确等,清单见 agent 报告)。

教训:修复 diff 自身的复审价值再次印证(api2 的 v6 半边残留、cmd1 的权限面
回归都是修复引入/未闭合的新问题);探针判据要落到「能区分修复前后」的字节位
(F2 首版探针两个世界同绿,等于没测)。
