# GFRGuard TODO

## 0. 代码审查发现 (2026-07-19)

全量代码审查（daemon 核心 / 三通道 / VFS+recover / common+测试，4 路并行）。
注：close 事件做内容检测是有意的实现选择（专利规避），文档"写时检测"措辞同为有意，**不在问题清单内**。

### 0.1 高严重度（防护失效或权限提升，优先修）

| # | 位置 | 问题 | 修法 |
|---|------|------|------|
| H1 ✅ | daemon/gfrguardd_cloud.c:189,224 | ~~**root 命令注入**~~ | 已修 (2026-07-19)：popen/system → fork+execvp 数组传参消除 shell，另加 task_name 白名单 `[A-Za-z0-9_.-]` 提前拒绝 |
| H2 ✅ | vfs/vfs_gfrguard.c:336-346 | ~~**30 秒"新窗口"逻辑用已加密内容覆盖好备份**~~ | 已修 (2026-07-19)：改为"first copy wins"——备份已存在即保留，永不覆盖，窗口特殊情况整体消除 |
| H3 ✅ | recover/gfrguard_recover.c:195-196 | ~~**restore 以 root open 跟随符号链接可提权**~~ | 已修 (2026-07-19)：valid_restore_path 拒绝非绝对/含 `..` 路径；lstat 不跟随符号链接；copy_file 双端 O_NOFOLLOW + fd 上 fchown/fchmod（顺带修掉 setuid 位照搬和 chown 竞态）；delete_created_one 同套校验 + 符号链接只 unlink |
| H4 ✅ | daemon/gfrguardd_ftp.c:184-186 | ~~**/proc/net/tcp IP 字节序反转**~~ | 已修 (2026-07-19)：改从低字节起打印（`0100007F` → 127.0.0.1） |
| H5 ✅ | daemon/gfrguardd_ftp.c:236-246,290 | ~~**未初始化内存读取**~~ | 已修 (2026-07-19)：ftp_resolve_session 入口先清空两缓冲区，成功判定改用两个 resolver 的返回值而非字符串内容 |
| H6 ✅ | daemon/gfrguardd_blocker.c:78-80,94,174-191 + recover:357-369 + vfs:211 | ~~**封锁/解封格式三方错配**~~ | 已修 (2026-07-19)：blocked 文件定死单一格式"裸 IP 每行"。blocker_execute 收显式 client_ip + inet_pton 校验（cloud task_name / local `local:<pid>` / FTP fallback 空串全被同一道闸门挡掉）；main.c 仅 SMB/FTP 传 IP（cloud 用户接口 mock 中，预留不写；local 由 kill 处置不写——pname 无消费者且 prctl 改名即绕过，评审结论不写）；scorer_blacklist_auto_add 补 inet_pton 校验堵 sync 路径垃圾；recover unblock 改用 blocker_unblock（删除重复的 remove_from_blocked 及死代码 get_session_key_for_event），`unblock <ip>` 行精确匹配，未找到返回"Not in blocked list"不再静默成功；blocker.h 注释同步修正 |
| H7 ✅ | daemon/gfrguardd_main.c:753-756 | ~~wire 数据未强制 NUL 终止~~ | 已修 (2026-07-19)：recv 长度校验后对 5 个字符串字段强制末尾置 0 |
| H8 ✅ | daemon/gfrguardd_entropy.c + yara.c | ~~对不可信路径无条件 open() 可永久阻塞主线程~~ | 已修 (2026-07-19)：entropy 与 yara 扫描统一 open(O_RDONLY\|O_CLOEXEC\|O_NONBLOCK) + fstat 确认 S_ISREG，FIFO/挂死 FUSE 被同一道闸门挡掉 |
| H9 ✅ | daemon/gfrguardd_session.c:25-45 | ~~会话表满即静默失去保护~~ | 已修 (2026-07-19)：新增 last_seen，表满时淘汰最久未活跃的非 blocked 会话并记 SESSION_EVICT 日志；全 blocked 才丢弃并记 SESSION_TABLE_FULL |
| H10 ✅ | daemon/gfrguardd_cloud.c:140 + ftp.c:266 | ~~事件线程内 sleep 2.5s/0.5s~~ | 已修 (2026-07-19)：宽限期移入 fork 出的 reaper 子进程（继承 pid 列表副本，主线程立即返回），由 restore_reap_children 收割；顺带修 M13 日志归属——restore_reap_children 只给自动恢复子进程记 AUTO_RESTORE_*，kill reaper/smbcontrol 静默收割 |
| H11 ✅ | common/rguard_db.c:424 | ~~db_query_created_by_event 在 step 中执行回调~~ | 已修 (2026-07-19)：先收集 (id,path) 数组、finalize 后再回调；realloc/strdup 失败返回 RGUARD_ERR_DB |
| H12 ✅ | common/rguard_backup.h:43-48 | ~~copy_file_range 按 EOF 而非 size 截断~~ | 已修 (2026-07-19)：每次调用上限 min(1MB, size-total)，size=0 不拷；顺带 read/copy_file_range EINTR 重试、write(0) 按失败处理 |

### 0.2 中严重度

| # | 位置 | 问题 | 修法 |
|---|------|------|------|
| M1 ✅ | daemon/gfrguardd_fanotify.c:702-717 | ~~MOVED_FROM/TO 配对无 rename cookie，同进程同目录交错 rename 错配，路径/扩展名分析/created 清理全作用于错误文件~~ | 已修 (2026-07-19)：g_moved_from 加 pairable——连续第二个 FROM 说明交替被破坏（fanotify 无 cookie 可核对），下一个 TO 强制按未配对处理，宁缺毋滥 |
| M2 ✅ | daemon/gfrguardd_fanotify.c:460 | ~~无 channel 时 perm 事件不 drain 不应答，reload 后残留 FAN_OPEN_PERM 使发起 open 的进程无限挂起~~ | 已修 (2026-07-19)：删掉 g_ch_count==0 提前返回——无 channel 时 find_channel 自然回 NULL，响应保持 ALLOW，同一条路径 drain |
| M3 ✅ | daemon/gfrguardd_main.c:272-280 | ~~子开关过滤逻辑错误：cloud/ftp/host 事件只在三开关全关时才丢弃，单来源未按各自开关门控~~ | 已修 (2026-07-19)：switch 每 case 查各自开关并记 PROTECTION_OFF 原因 |
| M4 ✅ | daemon/gfrguardd_fanotify.c:892 + main.c:413-414 | ~~备份路径拼接无截断检查，深目录文件 snprintf 静默截断 → 备份写错位置、DB 与落盘不一致、restore 找不到~~ | 已修 (2026-07-19)：两处均检查 snprintf 返回值，截断记 BACKUP_PATH_TRUNCATED；fanotify 侧返回 ERR_BACKUP，main 侧跳过 DB 记录（不落不一致数据） |
| M5 ✅ | daemon/gfrguardd_main.c:200 | ~~reload 时 fanotify_start_perm_thread() 返回值未检查，pthread_create 失败则所有 FAN_OPEN_PERM 无限挂起且无日志~~ | 已修 (2026-07-19)：reload 与启动两处均重试一次，仍失败记 PERM_THREAD_DEAD |
| M6 ✅ | daemon/gfrguardd_scorer.c:179-184 | ~~例外文件后缀匹配无路径边界~~ | 已修 (2026-07-19)：要求匹配点前字符为 `/`，单条规则覆盖所有形态 |
| M7 ✅ | daemon/gfrguardd_local.c:107-109 | ~~starttime 被覆写，PID 复用保护失效~~ | 已修 (2026-07-19)：starttime 进入 client_ip（`local:<pid>:<start>`）→ 派生 skey 天然按进程实例区分；local_kill 前重读 /proc/pid/stat 复核 starttime，复用则不杀 |
| M8 ✅ | daemon/gfrguardd_cloud.c:54 | ~~rclone 识别用 strstr 匹配任意参数位置~~ | 已修 (2026-07-19)：改为 argv[0] basename == "rclone" 精确判断 |
| M9 ✅ | daemon/gfrguardd_cloud.c:191-216,225 | ~~popen/system 无超时：neo-croner 挂死则主事件线程永久阻塞~~ | 已修 (2026-07-19)：query 改 pipe2(O_CLOEXEC)+poll 空闲超时（有数据即重置），delete 走新增共享 fan_wait_timeout；超时 SIGKILL 收割。NEO_CRONER_TIMEOUT_MS 编译期可覆盖（测试 400ms）；fake neo-croner 5 用例（解析/注入拒绝/挂死超时/退出码/缺 binary） |
| M10 ✅ | daemon/gfrguardd_blocker.c:84-100 | ~~read_file_text 返回值被吞：文件存在但读失败时 content=NULL → write_atomic 用单条记录重建，已有封锁条目全丢~~ | 已修 (2026-07-19)：读失败即 close(lock)+return -1。新增 test_blocker.c（11 用例，blocker 此前零测试）——读失败用例用 setuid(nobody) 制造真 EACCES，第一版因锁文件残留意外转绿，改独立目录后才真红再修绿 |
| M11 ✅ | daemon/gfrguardd_ftp.c:140-193 | ~~/proc/net/tcp 单次 read 4KB 截断后 inode 匹配不上，fallback 形同虚设；未查 tcp6~~ | 已修 (2026-07-19)：read_proc_file 循环读至 EOF（上限 4MB）；tcp+tcp6 都查；解析抽纯函数 ftp_tcp_find_remote（v4 低字节起/v6 按词反转+inet_ntop）；顺手删 parsed<2 兜底错误分支（取的是 local 地址）。test_channels 含 >4KB 目标行回归用例 |
| M12 ✅ | daemon/gfrguardd_local.c:74-84,115 | ~~白名单仅按 comm 精确匹配：进程改名 "sshd" 即绕过 local 通道~~ | 已修 (2026-07-19)：改验 /proc/pid/exe 绝对路径白名单（Yocto 镜像路径固定）；无 exe 的内核线程回退 comm 前缀匹配（顺带修掉 kworker/0:1H 精确匹配永假）；/tmp/sshd 式 FS 改名同被挡。local_whitelist_match 纯函数 8 用例锁定 |
| M13 ✅ | daemon/gfrguardd_restore.c:33-41,49 | ~~fork 子进程继承全部 fd（fanotify/DB/socket 泄漏）；waitpid(-1) 抢先收走 blocker 的 smbcontrol 并误记日志~~ | 已修 (2026-07-19)：fd 审计——daemon 长生命周期 fd 全部 O_CLOEXEC（socket/epoll/timerfd/socketpair/fanotify/sqlite 实测 cloexec=1），cloud pipe 改 pipe2(O_CLOEXEC)，ftp /proc 打开补齐；exec 后 recover 进程零继承。误记日志部分 H10 已修（只给登记的自动恢复子进程记日志，其余静默收割——收割本身是必要的，否则 reaper 成僵尸） |
| M14 ✅ | daemon/gfrguardd_ftp.c:299 + local.c:112 | ~~fallback 用路径当 session，评分被打散永不达阈值~~ | 已修 (2026-07-19)：fallback 归入固定会话 `ftp@unknown` / `local@unknown`，评分跨文件累计；"unknown" 非合法 IP 被 blocked 闸门自然拒绝 |
| M15 ✅ | daemon/gfrguardd_cloud.c:316-318 | ~~`.tmp` 排除过宽~~ | 已修 (2026-07-19)：去掉 `.tmp` 兜底，只保留 `.partial~` / `.rclone-tmp` |
| M16 ✅ | daemon/gfrguardd_ftp.c:257-268 | ~~PID 复用 TOCTOU：仅靠 comm=="vsftpd" 判断，复用为另一 vsftpd 进程时杀错会话~~ | 已修 (2026-07-19)：ftp_resolve 捕获 starttime 入 ctx->proc_start；ftp_block_execute(pid, expected_start) kill 前 fan_proc_stat 复核 comm+starttime；/proc/stat 解析收编为 fanchannel 共享 fan_proc_stat（local/ftp 一份）。kill 行为 4 用例（prctl 改名子进程真杀/真留） |
| M17 ✅ | daemon/gfrguardd_space.c:20-21 | ~~db 未判空；头注释 "-1 = still over" 与实现不符（清理后从不复查直接 return 0）~~ | 已修 (2026-07-19)：抽出 used_percent()，清理后重新 statvfs，仍超限返回 -1，日志加 after_cleanup_pct；新增 test_space.c（7 用例，space 此前零测试） |
| M18 ✅(设计确认) | vfs/vfs_gfrguard.c:201-211 | ~~封禁匹配只按 IP~~ | 非缺陷 (2026-07-19 确认)：IP 级阻断是系统设计粒度——blocker_execute、scorer_blacklist_auto_add、blocker_sync_blacklist 三条链路均为 IP 级；威胁模型中被感染的是 Windows 机器而非用户，同 IP 其他会话大概率同机；NAT 连坐在 NAS 内网部署中极少见 |
| M19 | vfs/vfs_gfrguard.c pwrite | ✅ 已修：rguard_file_state 加 event_sent 标志，每个文件句柄只发一次 WRITE 事件（permissive 备份失败不再刷事件洪水） |
| M20 | vfs/vfs_gfrguard.c close | ✅ 已修：内容比较只对 ≤64MB(GFR_CONTENT_COMPARE_MAX) 文件做，大文件保留 modified_count（罕见误报优于卡死 SMB 会话） |
| M21 | vfs/vfs_gfrguard.c do_backup | ✅ 已修：src open 加 O_NOFOLLOW + fstat 确认 S_ISREG，拷贝尺寸/时间戳改用 fd 上的 fst（stat→open TOCTOU 消除） |
| M22 | daemon/gfrguardd_blocker.c + recover | ✅ 已修：blocked.lock flock 包住 execute/sync/unblock 三处读改写；read 循环+EINTR；write≤0 判失败；rename 后 fsync 目录 |
| M23 ✅ | common/rguard_config.c:193-196 | ~~entropy_threshold 无范围校验：<0 一切文件判高熵（误报洪水+误封禁），>8 永不触发~~ | 已修 (2026-07-19)：随 H13 校验块一并落地——weights≥0、四窗口>0、entropy∈[0,8]、0<percent≤100、cleanup_days>0、delay_seconds≥0（注：中途曾因误操作丢失该块，已按 TODO 描述重建并全量回归） |

| M24 ✅ | daemon/gfrguardd_session.c:12 vs common/rguard_hash.h:20 + tests/test_session.c:8 | ~~daemon 的 FNV 偏移基掉了一位数字（`...603` 应为 `...6037`），根本不是 FNV-1a；rguard_hash.h 注释谎称常量一致；test_session.c:8 把错误常量固化为期望值（锁死 bug 的假测试）~~ | 已修 (2026-07-19)：删 session 私有 fnv1a64，session.c/main.c 统一用 rguard_fnv1a64（单一实现，头文件注释标明禁止再抄）；test_session.c 期望值改为正确常量并先红后绿验证 |
| M25 ✅ | common/rguard_db.c:319-328,351-360 | ~~查询收集行 realloc 失败 break 后仍返回 RGUARD_OK → 调用方拿到静默截断结果集（restore 漏文件）~~ | 已修 (2026-07-19)：两处 realloc 失败即 free + 返回 RGUARD_ERR_DB |
| M26 ✅ | common/rguard_protocol.h:52-70 | ~~协议无 magic/version 字段，仅靠 4608 字节尺寸判兼容，字段语义变化时新旧组件静默互误解~~ | 已修 (2026-07-19)：_reserved[0] 命名 proto_version + RGUARD_PROTO_VERSION=1，尺寸不变（旧对端读 0，向后兼容）；发送端 vfs 两处 + fanotify_build_event_msg 打版本；接收端 >当前版本丢弃并记一次 PROTO_VERSION_DROP；注明 NUL 终止契约；test_protocol 锁定 offset/尺寸 |
| M27 ✅ | common/rguard_log.c:95,103-108 | ~~g_level 锁外读构成数据竞争；session_key/detail_json 未转义 `\n`/`\r` → 用户可控字段可伪造日志行（日志注入）~~ | 已修 (2026-07-19)：g_level 改 _Atomic；event/session_key/detail_json 写入前 escape_line 转义 `\n`/`\r`；新增 test_log.c（6 用例，注入用例：一条写入只产一行） |
| M28 ✅ | common/rguard_db.c:520 | ~~db_get_cloud_task_config 未找到返回 -1，与 RGUARD_ERR_* 正数枚举不一致~~ | 已修 (2026-07-19)：枚举新增 RGUARD_ERR_NOT_FOUND=8 + strerror；未找到返回该码，test_db 锁定 |
| M29 ✅(新发现) | common/rguard_db.c db_upsert_event | ~~空 status/action_taken 绑 NULL 撞 NOT NULL 约束，upsert 必败~~（扩 test_db 时试出；生产调用方恰好都设置了这两字段所以未爆） | 已修 (2026-07-19)：与 db_insert_event 一致绑定 "active"/"none" 默认值；test_db upsert 用例锁定 |
| M30 ✅(新发现) | daemon/gfrguardd_yara.c 规则加载 | ~~symlink 环/同文件重复加载 → 重复规则名编译错误 → 编译器带错误状态继续 add 触发 libyara assert 直接 abort~~（test_yara symlink_loop 用例试出） | 已修 (2026-07-19)：按 (dev,ino) 去重同一规则文件；正式 add 失败即判定编译器被污染、整个加载 -1 而不是继续裸奔 |
| M31 ✅(新发现) | Makefile 头文件依赖缺失 | ~~%.o 只依赖 %.c：config.h 删字段后旧 .o 不重编，同一二进制混入两种结构体布局（space.max_usage_percent 读成 0，集成测试拿损坏二进制空转）~~ | 已修 (2026-07-19)：COMMON_CFLAGS 加 -MMD -MP + -include dep 文件；touch 头文件验证全量重编 |

### 0.3 低严重度（批量收录，随修随清）

**daemon 核心**
- ~~fanotify.c:587-632 legacy 路径不处理 FAN_Q_OVERFLOW，丢事件后不 rewalk 形成监控盲区~~ ✅ (2026-07-19)：legacy 路径补同款处理（记日志+g_need_rewalk）
- ~~main.c:396-402 + fanotify.c:336-394 定时器路径与 perm 线程对 g_chrt[] 弱数据竞争（pending 改 _Atomic bool）~~ ✅ (2026-07-19)：pending 改 _Atomic bool
- ~~fanotify.c:565 队列写失败静默丢 perm 事件，无日志无计数~~ ✅ (2026-07-19)：写不满即计数，每 1000 条记一次 EVENT_QUEUE_DROP
- ~~fanotify.c:104 readlink 不检测截断；out_len==0 时 underflow（API 隐患）~~ ✅ (2026-07-19)：out_len==0/截断均返回 -1
- ~~yara.c:36-37 规则目录递归跟随符号链接无深度限制，symlink 环 → 栈溢出~~ ✅ (2026-07-19)：深度上限 8 + (dev,ino) 去重（symlink 环用例顺带试出 M30 assert 崩溃）
- ~~yara.c:123-150 yara_engine_init 前半段无效双重初始化，删 123-148 行直接调 init_clean~~ ✅ (2026-07-19)：已删，直接调 init_clean
- ~~yara.c:68 正式 yr_compiler_add_file 返回值被吞，失败仍计入 loaded~~ ✅ (2026-07-19)：正式 add 失败即判定编译器污染，整个加载 -1（M30 一并）
- ~~main.c:703-705 timerfd_create 返回值未检查，失败则 space_check 静默失效~~ ✅ (2026-07-19)：失败记 TIMERFD_FAILED 并退出（不裸奔）
- ~~session.c:75 window_long 到期重置 is_blocked=false，30 余秒后 fanotify 通道阻断语义失效且重复触发 blocker~~ ✅ (2026-07-19)：is_blocked 不随窗口滑动清除——与 blocked 文件/auto-blacklist 同生命周期；test_session long_reset 语义反转锁定，process_msg 用例验证
- ~~fanotify.c:578-579、main.c:336 死代码（skey、bl_user 构造后未使用）~~ ✅ (2026-07-19)：已删
- ~~scorer.c:288-306 FIFO 驱逐后 auto_ip_hashes 与 auto_ips 错位（当前无人读，埋雷）~~ ✅ (2026-07-19)：全仓库确认 auto_ip_hashes 只写不读，直接删除该字段及写入点——说谎的死代码不如没有；顺带补 scorer.c 缺失的 stdio.h（snprintf 隐式声明）
- ~~fanotify.c:196-210 epoll_ctl 失败路径无日志~~ ✅ (2026-07-19)：两路失败均记 EPOLL_ADD_FAILED
- ~~session.c:9-18 fnv1a64 与 rguard_hash.h 重复实现（与 M24 一并处理）~~ ✅ (2026-07-19)：随 M24 删除

**三通道**
- ~~cloud.c:258-267 / ftp.c:308-310 日志 JSON 未转义（`"`、`\` 破坏结构）~~ ✅ (2026-07-19)：rguard_log.h 新增 rguard_json_escape（引号/反斜杠/控制字符），cloud expression/command 与 ftp cmdline 两处现场修复；test_log 覆盖
- ~~cloud.c:104-130 进程树 >256 静默截断，残余进程不收 SIGKILL，无日志~~ ✅ (2026-07-19)：超限记 PROC_TREE_TRUNCATED（收集到的照杀）
- ~~blocker.c:107-115 fork 失败静默跳过仍返回 0；waitpid 无超时，smbcontrol 挂死卡主线程~~ ✅ (2026-07-19)：fork 失败记 BLOCKER_FORK_FAILED；waitpid 改 rguard_wait_timeout(5s)（新 common/rguard_proc.h，header-only，recover 也可链接）
- ~~blocker.c:38-52 write 返回 0 理论死循环；rename 后未 fsync 目录；tmp 名超长被截断~~ ✅ (2026-07-19 前会话)：write≤0 判失败、rename 后 fsync 目录已落地（M22 一并）
- ~~blocker.c:29 单次 read 不循环，信号中断致内容截断、line_exists 误判~~ ✅ (2026-07-19 前会话)：read 循环+EINTR（M22 一并）
- ~~restore.c:36 delay_seconds 负值 cast unsigned 后子进程睡眠数百年~~ ✅ (2026-07-19)：>0 才 sleep（guard 本就在），H13 配置校验 delay_seconds≥0 兜底；test_restore 负值用例
- ~~cloud.c:389 / ftp.c:377,385 / local.c:186 fanotify_channel_setup 返回值被忽略，mark 失败仍打 READY~~ ✅ (2026-07-19)：三通道 setup 失败均记 CHANNEL_SETUP_FAILED 带路径
- ~~ftp.h:22 / blocker.h:23 头注释与实现脱节~~ ✅ (2026-07-19)：ftp.h 重写（含新暴露函数契约）；blocker.h 注释 H6 已同步
- ~~ftp.c:172-178 parsed<2 兜底解析取的是 local 地址而非 rem，从未正确，建议删~~ ✅ (2026-07-19)：随 M11 重写删除
- ~~fangate.c:35 REALTIME 回拨使 now-last_sent 为负，（会话，inode) 长期被抑制 → 改 CLOCK_MONOTONIC~~ ✅ (2026-07-19)：调用点改 CLOCK_MONOTONIC

**VFS / recover**
- vfs:459-471 connect 因 blocked 被拒时泄漏 sock_fd（return 前未 close）
- vfs:753-755,875 pwrite/ftruncate 延迟备份成功后不写 fst->backup_path，CONTENT_SAME 去重被静默跳过
- vfs:952-954,1001-1004 rename/unlink 失败后仍向 daemon 发送成功语义事件，干扰评分
- vfs:642,762,837 strict 模式备份失败返回 ENOSPC 误导客户端重试，与 unlinkat 的 EACCES 不一致 → 统一 EIO/EACCES
- vfs:294-303 compute_backup_path 用 strstr 取首个 `/<share>/` 匹配，同名目录截错位置；回退分支同 basename 互相覆盖备份 → 用 connectpath 长度前缀剥离
- vfs:673-674 risky 分支在 NEXT_OPENAT 失败时也发 WRITE 事件
- vfs:264,608 等 所有路径 snprintf 截断静默 → 检查返回值，截断记日志跳过事件
- vfs:785-845 ftruncate 不区分缩短/增长，Windows 预分配增大文件也触发全量备份+fsync，写放大
- recover:204-205 chown/chmod 返回值未检查；chmod 照搬 st_mode 含 setuid 位 → 用 `& 0777`
- ~~recover:249-302 delete_created_one 只处理普通文件，目录删除整段注释掉；dangling 符号链接误计 deleted~~ ✅ (2026-07-19)：目录走 rmdir（非空不递归——攻击者命名的树不归我们 rm -rf）；dangling 符号链接用例证明 unlink 行为正确（lstat 不跟随）；test_recover.c 覆盖
- ~~recover:180 quarantine rename 静默覆盖同名已有隔离文件（证据丢失）~~ ✅ (2026-07-19)：quarantine_unique() 追加 .N 选空位，test 红→绿
- ~~recover:379-399 status 只读 blocked 文件前 4095 字节，会话多时计数截断~~ ✅ (2026-07-19)：循环读至 EOF 计数+全量打印；test 2000 条 (~20KB) 验证
- ~~recover:220-235,279-291,339-343 大段注释掉的死代码，要么实现要么删~~ ✅ (2026-07-19)：目录分支实现为 rmdir，其余注释死代码删除；顺带 copy_file EINTR 重试、路径宏 #ifndef 可覆盖（测试重定向用）

**common**
- ~~db.c:111-116 db_close 忽略 sqlite3_close 返回值，BUSY 时句柄静默泄漏 → 检查或用 close_v2~~ ✅ (2026-07-19)：失败回退 close_v2 并返回 RGUARD_ERR_DB
- ~~db.c:100-103 唯一索引迁移在存量库有重复行时静默失败，去重失效无人知晓~~ ✅ (2026-07-19)：迁移失败打 stderr 并拒绝打开（去重失效不能裸奔）
- ~~db.c:458-460 db_get_max_daily_seq LIKE 模式未转义通配符 → 加 ESCAPE~~ ✅ (2026-07-19)：改用 strpbrk 拒绝含 `%_` 的前缀（前缀本就该是日期数字），测试锁定
- ~~db.c:383-400 db_cleanup_restored 负 days 生成非法 modifier，静默一行不删返回 OK~~ ✅ (2026-07-19)：负 days 直接 RGUARD_ERR_DB，测试锁定
- ~~backup.h:57-65 read 遇 EINTR 不重试（SIGHUP 频发环境）；write 返回 0 理论死循环~~ ✅ (2026-07-19 前会话)：随 H12 已修（EINTR 重试、write(0) 判失败）
- ~~config.c:14-29 read_file 无大小上限，巨型配置直接 malloc~~ ✅ (2026-07-19)：上限 4MB，超限 EFBIG 拒读
- ~~config.c:97-106 dir_writable 注释与实现不符（注释撒谎）~~ ✅ (2026-07-19)：注释删除，实现如实
- ~~config.c:215 等 名单超上限静默丢弃多余项，无告警~~ ✅ (2026-07-19)：全部 10 个名单循环超限打 stderr 告警
- ~~config.c:76-81 copy_string 超长静默截断，配置项静默失效无提示~~ ✅ (2026-07-19)：截断打 stderr 告警
- ~~hash.h:80-84 lookup_len 注释宣称前缀匹配，实现只等长匹配（注释误导）~~ ✅ (2026-07-19)：注释改为如实描述等长匹配+调用方逐级探测；test_hash.c 覆盖（碰撞邻走/SORT_BY_HASH 双数组同步）
- log.c 无日志轮转/每行 fflush —— ⏸️ 设计选择不修 (2026-07-19)：轮转属新特性（应交给 logrotate/systemd）；每行 fflush 是崩溃取证的有意取舍，事件风暴由 fangate 前置限流

### 0.4 结构性问题（设计层面）

**S1 ✅ (2026-07-19) 三通道 handler 已统一为公共骨架**
新增 `gfrguardd_fanchannel.c/.h`：`fan_channel_handle` 收编 mask 判定、blacklist 检查、backup+fstat、gate/queue、fill_notify/submit；通道只剩 `resolve`（身份解析/白名单/临时文件排除）与 `block`（kill vsftpd / SIGKILL / neo-croner+kill 树）两个回调，另有可选 `on_blacklist_deny`（local 的 kill）。注册改为 `fan_channel_dispatch` + 静态 `struct fan_channel{ops, policy}`。漂移已消除：cloud 补齐 blacklist 检查与 file_uid/gid/mode（fstat 五字段全通道统一）；ftp/local 的 `extern scorer_is_blacklisted` 声明 hack 移除。CMakeLists 与 Makefile（wildcard）均已收录新文件，9 套单测全过。
遗留：各通道 resolve 内部的已知问题（M6/M7/M8/M14/M15）未在此轮改动——重构保持行为不变，逐项修见 0.2 表。

**S2 ✅ (2026-07-19) 标识格式已收归单一事实源**
`rguard_protocol.h` 新增 `rguard_make_session_key()`——`username@client_ip` 格式的唯一定义点。骨架 `fan_channel_handle` 在 resolve 之后统一推导 skey（通道不再各自拼接）；process_msg、VFS（原 make_session_key 本地副本删除，8 处调用点全部切换）同用此函数。H6 的 blocked 文件定死裸 IP + inet_pton 闸门后，strrchr('@') 自行解释已全链路清除。残留：cloud 通道 client_ip 字段塞 task_name 的语义滥用（等用户接口落地后清理）；M18（VFS 封禁按 IP 连坐 NAT 用户）为有意降级待确认。

**S3. 测试覆盖结构性失衡**
- 完全无测试：blocker、restore、fanotify、cloud、ftp、local、space、yara、main、vfs_gfrguard、gfrguard_recover、rguard_log——被测的 5 个（scorer/session/blacklist/fangate/entropy）恰是纯逻辑最易测的部分，事件处理/阻断/恢复/清理这些核心动作全部裸奔
- ~~test_db.c（34 行最弱）：update 族、created_files 三函数、cloud_task_configs 三函数、去重、字段 roundtrip 全零覆盖，断言只验行数~~ ✅ (2026-07-19)：扩至 20 个用例 70 断言——字段 roundtrip 全字段比对、(event_id,path) 去重、update/upsert MAX 语义、restore_status、created_files 增删查、cloud_task 三函数+最新优先+restored 不再返回、daily_seq 隔日隔离+通配符拒绝、cleanup 负 days；扩写即试出 M29 upsert NOT NULL 必败
- test_session.c:8 把错误 FNV 常量固化为期望值（假测试，见 M24）
- test_scorer.c：~~无窗口滑动重置~~（session 侧 short_window/long_reset 已有）、~~cloud 独立窗口~~（窗口选择在 fanotify/main 全局态内，单测不可达，归集成测试）、~~high(60)/critical(80) 边界用例~~；~~`same_50pct` 断言 `<=29` 过弱（score=0 也过）~~ ✅ (2026-07-19)：补 below_high/at_high/below_critical/at_critical_80 四边界、delete_cap 精确 ==60、same_50pct 强化为 raw=60 时 ==29、补 80%/66%/33% 三档 pct 边界、entropy+ransom_ext 组合加权
- rguard_hash.h 零直接测试（碰撞邻走、SORT_BY_HASH 双数组同步）
- ~~test_main.h:19 ASSERT 失败直接 return，掩盖同测试后续全部失败，覆盖统计虚高~~ ✅ (2026-07-19)：全部断言宏改为非致命（记录失败继续跑），clean 重建 13 套无级联崩溃——现有测试无人依赖提前 return

**修复优先级**：H1（root 注入）→ H2/H3（备份污染 + restore 提权，核心恢复能力）→ H4/H5/H6（ftp 解析双坏 + 封锁错配，防护失效）→ H7/H8（本地攻击面）→ H13（负权重绕过评分）→ S1/S2（结构统一，防止下一份拷贝继续漂移）。

---

## fanotify 通道测试环境 (2026-07-16)

**当前环境**：WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2)

**fanotify_init 失败原因**：

```
fanotify_init(FAN_CLASS_CONTENT) → EPERM (Operation not permitted)
fanotify_init(FAN_CLASS_NOTIF)   → EPERM (Operation not permitted)
```

| 检查项 | 结果 |
|--------|------|
| `CONFIG_FANOTIFY` | ✅ `=y` — 内核编译了 fanotify |
| `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` | ✅ `=y` — 支持 FAN_OPEN_PERM |
| `CAP_SYS_ADMIN` | ✅ 有（root 用户） |
| **seccomp** | ❌ `Seccomp: 2` + `Seccomp_filters: 2` — WSL2/Docker seccomp 过滤了 `fanotify_init` 系统调用 |

**结论**：是 **容器安全限制（seccomp）**，不是内核不支持也不是权限不足。WSL2 和 Docker 容器默认通过 seccomp profile 禁用了 fanotify 相关系统调用。

**fanotify 内核要求**（供 VM 环境参考）：
- Linux kernel ≥ 2.6.36
- `CONFIG_FANOTIFY=y`
- `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`（需要 FAN_OPEN_PERM 阻断模式）
- 进程需 `CAP_SYS_ADMIN`（即 root）
- **不能在 WSL2 或 Docker 容器内测试**（seccomp 限制）

**下一步**：在虚拟机（VirtualBox/VMware/KVM）中安装 Debian 12，以 root 运行 `gfrguardd`，实测 fanotify 三通道（FTP/Cloud/Local）的完整行为。

---

## 威胁模型纠正 (2026-07-07)

```
错误理解：NAS 自己感染 Linux 勒索 → YARA 检测 Linux ELF 二进制
正确理解：Windows 客户端感染勒索 → 通过 SMB 覆盖写 NAS 文件 → VFS 拦截文件操作

VFS 模块看到的是"文件被改写的内容"，不是"勒索软件在运行"。
主机型 Linux ELF 勒索检测规则不适用于 VFS 场景。
Vendor 规则集（Elastic/signature-base/ReversingLabs）已移除。
```

### VFS 层能检测的

| 层级 | 检测对象 | 方法 |
|------|---------|------|
| **内容** | 被写入的赎金信文本 | `ransom_notes.yar` — 扫描通过 SMB 写入的文件内容 |
| **内容** | 被加密文件（高熵 + 特定扩展名） | `encryption.yar` + 熵检测 |
| **行为** | 短时间批量 rename/write/delete | 行为评分（modified_count, ext_change, mass_delete, yara 命中） |
| **行为** | 客户端 IP 信誉 | 黑名单 + 会话级阻断 |

### VFS 层检测不到的

- 客户端上运行的勒索二进制本身（不在 NAS 上执行）
- Linux ELF 勒索（NAS 自己不被感染——攻击面是 Windows 客户端通过 SMB 协议）

## 1. 样本与验证策略（已纠正）

| 样本类型 | 用途 | 状态 |
|---------|------|------|
| **赎金信文本** (14 份真实赎金信) | `ransom_notes.yar` TP 验证 | ✅ 11/14 家族可检测 |
| **被加密文件** (.locked/.RHKRC/.dontdel/.encrypt 等） | `encryption.yar` TP 验证 + 熵检测校准 | 🟡 28 份合成样本已验证逻辑，任意获取真实样本 |
| **正常文件** (~15,000 系统文件) | FP 基线 | ✅ 0 FP |
| **GonnaCry Python 脚本** (83 .py) | `scripts.yar` TP 验证 | ✅ 3/83 命中 |
| **Windows PE 勒索** (33 个) | 交叉平台 FP 基线 | ✅ 0 FP |
| **Linux ELF** (476 + 143 MB) | FP 基线——规则不应误报 NAS 上的 Linux 二进制 | ✅ 0 FP |

### 待获取：真实被加密文件样本（通过沙箱导出）

```
来源：Any.Run 沙箱 (https://app.any.run/submissions)
过滤关键词：
  主搜索：.locked  .encrypt  .RHKRC  .conti  .akira  .WNCRY
  赎金信：HOW_TO_DECRYPT  README_TO_DECRYPT  RECOVER-YOUR-FILES  _readme
  标签：  ransomware  encrypts-files  creates-ransom-note

步骤：搜索 → 点进 submission → Files/Artifacts 面板 → 下载被加密文件 + 赎金信
需要：免费注册 Any.Run 账号

备选路线：
  - Triage (tria.ge) — 免费注册 + API key → 搜索 ransomware 沙箱运行 → 下载加密产物
  - 隔离 Windows VM 运行勒索样本 → 挂载 SMB 共享 → 抓取加密产物（可信度最高，耗时长）
```

## 2. YARA 自有规则

| 规则集 | 规则 | 适用性 | 状态 |
|--------|------|--------|------|
| `ransom_notes.yar` | 5/5 100% | ✅ **核心** — 赎金信文本通过 SMB 写入 | v2 (r21) |
| `encryption.yar` | 3/3 TP ✅ | ✅ **核心** — 被加密文件特征 | 合成样本已验证，待真实样本 |
| `families.yar` | 9/15 60% | 🟡 **辅助** — 仅当勒索二进制被拷贝到 NAS 时触发 | r21 LockBit/Hive |
| `linux.yar` | 5/5 | 🟡 **辅助** — 同上 | v2 (r21) |
| `scripts.yar` | 0/4 | 🟡 **辅助** — .bat/.ps1 可能被写入共享 | GonnaCry 已验证 TP |
| `custom_template.yar` | 0/5 | ❌ 模板占位 | 无需修 |

### ransom_notes.yar v2 (r21)

| 规则 | 检测内容 |
|------|---------|
| RansomNote_Generic | 赎金信通用短语（22 个模式） |
| RansomNote_Filename | 赎金信文件名（HOW_TO_DECRYPT, akira_readme 等） |
| RansomNote_TorLink | Tor 洋葱链接 + 支付上下文 |
| RansomNote_CryptoWallet | 加密币地址 + 赎金上下文（已去 Go stdlib FP） |
| RansomNote_DataLeak | 双重勒索威胁（数据泄露博客 + 下载威胁） |

### encryption.yar TP 验证 (2026-07-07)

28 份合成样本，覆盖 5 类：被加密文件(12)、赎金信(5)、密钥配置(2)、部分加密(2)、熵校准(7)。

| 规则 | 命中 | 说明 |
|------|------|------|
| `Ransomware_EmbeddedKey` | 2/2 ✅ | RSA/PEM 密钥 + JSON 配置字段 |
| `Ransomware_PartialEncryption` | 1/1 ✅ | encrypt_percent + chunk_size + ChaCha |
| `Ransomware_FileHeaderCorruption` | 4/12 ✅ | HERMES/WANACRY/wcry/key_footer；普通加密文件正确不匹配 |

熵校准：正常文件 4.4-4.9，加密文件 8.0，阈值 7.0 有 ≥2.0 安全余量。

## 3. 评分机制 (Scoring)

**优先级 P0**——VFS 场景下行为评分是核心检测手段。

8 项权重 + 3 级阈值未经过 SMB 覆盖写攻击数据验证。

路线：收集 Windows 勒索→SMB→NAS 的攻击行为数据 → 网格搜索校准权重(F1↑, FP<0.1%) → 窗口优化 → 自适应阈值。

## 4. 优先级

| P | 任务 | 状态 |
|---|------|------|
| P0 | ~~FP 基线扫描~~ | ✅ |
| P0 | ~~ransom_notes.yar 修复~~ | ✅ v2 (r21) |
| P0 | ~~Vendor 规则移除~~（威胁模型纠正后不适用） | ✅ |
| P0 | ~~encryption.yar TP 验证~~（合成样本 3/3，熵校准完成） | ✅ |
| P0 | **获取真实被加密文件样本**（Any.Run/Triage/VM 运行） | 🔴 |
| P0 | **Scoring: SMB 覆盖写行为建模 + 权重校准** | ⬜ |
| P1 | 被加密文件真实样本验证（拿到样本后跑 encryption.yar + ransom_notes.yar） | ⬜ |
| P1 | 去重（ransom_notes vs families vs linux 中功能重叠的规则） | ⬜ |
| P1 | 多模块目录拆分（common/vfs/cloud/ftp） | ⬜ |
| P2 | 规则升级机制 | ⬜ |
| P2 | Scoring: 自适应阈值 | ⬜ |

## 5. 立即可做

- **Any.Run 获取真实被加密文件样本**：注册 → 搜 `.locked`/`.encrypt`/`HOW_TO_DECRYPT` → 下载加密产物 + 赎金信
- **encryption.yar 真实样本回归**：拿到样本后替换合成样本重跑验证
- **评分参数文档化**：为每个权重标注依据（基于 SMB 协议行为，非主机行为）
- **规则去重**：ransom_notes.yar + families.yar + linux.yar 中功能重复项标记
- **生产日志分析**：统计 SMB 场景下每条规则的命中次数
