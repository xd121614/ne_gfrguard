# GFRGuard 特性列表

## 1. SMB 通道（VFS 模块 `vfs_gfrguard.so`）

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| 文件操作实时拦截 | openat/pwrite/ftruncate/renameat/unlinkat/mkdirat/close 九回调，客户端透明 | ✅ | FR-VFS-01 / L3[1]-[12] |
| O_APPEND 绕过防御 | append 打开不计风险，但 ftruncate 截断照样拦截备份 | ✅ | FR-VFS-01 |
| 删除前备份（fanotify 通道） | unlink 不经 open，内核无法提供内容——仅 SMB 通道具备 | — 能力边界 | design 3.3 固有限制 |
| 相同内容覆盖识别 | close 时 FNV-1a 比对备份与现文件，相同则 CONTENT_SAME 抑制评分（防批量部署误报） | ✅ | FR-VFS-03 / L3 |
| 会话阻断检查 | 每操作前查 blocked 文件（stat-mtime 纳秒缓存），命中 EACCES | ✅ | FR-VFS-04 / L3[3] |
| 事件上报 | AF_UNIX DGRAM fire-and-forget，EAGAIN 重试 ×3 | ✅ | FR-VFS-05 |
| 多 Samba 版本适配 | VFS 接口 49/51 条件编译（4.19.6 / 4.23.5） | ✅ | L3 双版本全绿 |

## 2. fanotify 通道公共能力（FTP / 本地 / 云）

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| open 同步拦截 + 备份 | FAN_OPEN_PERM 内核阻塞 open，黑名单 DENY + 写前备份（独立 perm 线程，防死锁） | ✅ | FR-FTP-01 等 / L3[13][14][19] |
| 递归目录监控 | nftw 遍历整树打 mark；新建/移入目录动态补 mark；溢出重遍历；缺失路径 60s 重试 | ✅ | L3[19][21] |
| 事件覆盖与 VFS 对齐 | FID group：MODIFY（覆盖写+truncate）/CREATE（含 mkdir）/DELETE/RENAME/CLOSE_WRITE | ✅ | L3[20]-[23] |
| 勒索后缀改名检测 | RENAME → EXT_CHANGE/RANSOM_EXT 评分 | ✅ | L3[23] |
| 洪泛抑制（fangate） | 同一 (会话,文件) 每评分窗口只计一次改写分，大文件上传不误判；备份/黑名单/CLOSE 不受门限 | ✅ | design 3.3 / L2 test_fangate + L3[24] |
| 自事件过滤 | daemon 备份/恢复回写不进评分管线（pid 过滤） | ✅ | design 3.3 |
| 内核降级兼容 | <5.9 无 FID 支持时自动降级为仅 CLOSE_WRITE 检测 | ✅ | design 3.3 |
| 事前拦截 delete/rename/mkdir | fanotify 无对应 perm 事件，仅能事后检测+阻断（内核能力边界，永不对齐 VFS） | — 能力边界 | design 3.3 固有限制 |

## 3. 通道专属能力

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| FTP 会话识别 | vsftpd cmdline 解析（本地/匿名/虚拟用户）+ socket-inode/UID 兜底 | ✅ | FR-FTP-01 / L3[13][15][17] |
| FTP 阻断 | FAN_DENY + SIGTERM vsftpd child + blocked 文件（与 SMB 互通） | ✅ | FR-FTP-02 / L3[13] |
| 云任务识别 | rclone cmdline → task_name，排除 `.partial~/.tmp/.rclone-tmp` 临时文件 | ✅ | FR-CLOUD-01 |
| 云任务阻断/恢复 | FAN_DENY + neo-croner delete + kill 进程树；任务配置存库，恢复时重注册 | ✅ | FR-CLOUD-02/03 |
| 云通道用户解析 | cloud_resolve_user 当前为 mock（固定 "cloud"），待 neo-croner query 补全 | ⚠️ | design 3.5 |
| 云通道 notify 检测 | 与 FTP/本地同构：CLOSE_WRITE→YARA/熵、MODIFY/DELETE/RENAME 评分；阻断经 cloud_block_task | ✅ | FR-DAEMON-04 / L3[26] |
| 本地进程追踪 | session=`<comm>@local:<pid>:<starttime>` 防 PID 复用；进程名白名单直接放行 | ✅ | FR-LOCAL-01 / L3[14][19] |
| 本地阻断 | FAN_DENY + SIGKILL + 审计表 | ✅ | FR-LOCAL-02 / L3[14][19] |

## 4. 检测引擎（gfrguardd 通用）

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| 会话级行为追踪 | 1024 槽哈希表，session_key 统一 `username@client_ip`（骨架 rguard_make_session_key 推导，通道只填字段）；双窗口 10s/30s（云通道独立 60s/180s，适配 API 节奏防慢速漏检） | ✅ | FR-DAEMON-02 / L2 test_session |
| 8 维加权评分 | modified/rename/delete/dirs/ext_change/ransom_ext/内容信号加权维度，阈值 30/60/80；评分以行为指标为主，不以"损坏文件数"驱动阻断 | ✅ | FR-DAEMON-05 / L2 test_scorer |
| 评分特殊规则 | CONTENT_SAME 比例抑制、纯删除封顶 60 不阻断；内容检测结果折入行为评分维度，不逐文件标记损坏状态、不按"损坏文件数"阻断 | ✅ | L2 test_scorer / L3[22] |
| Shannon 熵分析 | 前 8KB 采样，阈值 7.0；同一文件仅采样一次，同一会话首次命中后不再重复检测 | ✅ | FR-DAEMON-03 / L3[17][18] |
| 自有内容规则 | 赎金信/加密结构规则，容错编译；同一会话首次命中后中止后续扫描 | ✅ | FR-DAEMON-04 / L3[2][15][16] |
| 勒索扩展名检测 | RENAME 与 NEW_FILE 创建均比对扩展名库（127 种）并计分 | ✅ | FR-DAEMON-08 / L3[23][27] |
| 白/黑名单 | user/IP（含 CIDR/范围）；黑名单 auto_add 内存 FIFO（上限 64）+ 以 {ip, auto_add:true} 对象即时持久化 rguard-policy.json（重载/重启不丢，前端按标志区分手动/自动，均可删除） | ✅ | FR-DAEMON-10 / L2 test_blacklist + L3[8]-[12] |

## 5. 备份与恢复

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| 固定前像保护 | 对既有文件的覆盖写/truncate 统一创建前像（不依据文件重要性、进程恶意性或风险分选择性触发）；reflink→copy_file_range→read/write 三级回退，VFS/daemon 共享实现；仅限配置用户共享，OS 关键目录不纳入 | ✅ | FR-VFS-02/FR-FTP-03/FR-CONSTRAINT-01 / L2 test_backup + XFS 实测 |
| 按通道差异化阻断 | SMB: blocked+smbcontrol；FTP: DENY+kill；云: neo-croner；本地: SIGKILL | ✅ | FR-DAEMON-06 |
| 自动恢复 | CRITICAL 阻断后 fork+exec gfrguard-recover 还原 + 清理勒索新建文件 | ✅ | FR-DAEMON-07 / L3[4] |
| 手动恢复 CLI | restore / unblock / cloud-restore 子命令 | ✅ | FR-RECOVER-01 |
| 备份空间管理 | 60s 定时检查，超 80% 清理 30 天前已恢复备份 | ✅ | FR-DAEMON-09 |
| 保护范围 | 仅限明确配置的对外用户共享；OS 关键目录（/boot /etc /bin /sbin /lib /usr 等）不在保护范围内 | ✅ | FR-CONSTRAINT-01 |

## 6. 配置与运维

| 特性 | 说明 | 状态 | 需求/验证 |
|------|------|------|----------|
| JSON 统一配置 | rguard-policy.json 全量策略，全参数有默认值 | ✅ | FR-CONFIG-01 / L2 test_config |
| 总开关 + 四通道子开关 | protection.{enabled, smb, ftp, cloud_sync, host} | ✅ | FR-CONFIG-03 |
| 例外与文件类型过滤 | exceptions.files/folders + file_extensions.all/manual | ✅ | FR-CONFIG-04/05 / L3[5]-[7] |
| 配置热重载 | SIGHUP 重读策略/评分/名单/规则，并**重建 fanotify marks**（监控路径与通道开关变更即时生效；重载瞬间停/启 perm 线程，内核排队不丢事件） | ✅ | FR-CONFIG-02 / L3[25] |
| 结构化日志 | 分级事件码 + JSON 详情，events 表全程留痕 | ✅ | design 4.2 |
| 规则升级机制 | `gfrguard-rule-update`（独立 CLI 不常驻）：签名+哈希校验 → 目录级 rename 原子替换规则目录 → SIGHUP 热生效，reload 失败回退旧规则 | 📋 | FR-RULE-03 / architecture_v2 6.4.2 |
| 邮件告警 | 事件订阅 + 异步 SMTP + 10 分钟聚合发送 | 📋 | architecture 5.2.6 |
