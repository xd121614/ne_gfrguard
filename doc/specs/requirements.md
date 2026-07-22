# GF2000 APPCHECK 需求规格说明书

## 1. 概述 (Overview)

### 1.1. 背景与目标 (Background & Goal)

**背景**：勒索软件是全球企业面临的最严重安全威胁之一。在 NAS（网络附加存储）场景中，Windows 客户端感染勒索软件后，通过 SMB 协议对 NAS 上的共享文件进行覆盖式加密和破坏。传统基于主机 Agent 的 EDR 方案无法保护不可安装 Agent 的 NAS 设备，形成了防护盲区。

**核心问题**：如何在不修改 Samba 源码、不侵入客户端的前提下，在 NAS 端检测并阻断来自 SMB / FTP / 云同步 / 本地进程四种通道的勒索软件行为，同时将正常业务操作的误报控制在可接受范围内。

**产品目标**：构建一套多层次的 NAS 反勒索防护系统，覆盖 SMB 共享（VFS 层）、云连携（Google Drive / OneDrive）、FTP 、本地四种数据通道，通过文件操作拦截、内容分析、行为评分和会话阻断，实现对共享文件数据的实时保护。

**业务价值**：
- 为 NAS/Samba 文件服务器提供透明的反勒索保护，无需客户端安装任何软件
- 支持完全私有化部署，满足数据主权和合规要求
- 基于行为分析和内容检测的组合策略，相比纯签名方案适应性更强
- 统一覆盖 SMB、云同步、FTP、本地四种主流文件访问通道

### 1.2. 关键成功指标 (Success Metrics)

| 指标 | 目标值 | 衡量方式 |
|------|--------|----------|
| 已知勒索软件行为检出率 | ≥90% | 勒索软件模拟测试（赎金信写入、批量加密、批量重命名），覆盖四个通道 |
| 正常业务操作误报率 | <5% | 正常文件部署、配置更新、批量编辑不触发阻断 |
| 性能开销 | 不增加可感知延迟 | 启用防护前后各通道读写延迟对比 |
| 系统稳定性 | 0 次业务进程崩溃 | 连续 7×24 小时压力测试（smbd/vsftpd/rclone 无崩溃） |

### 1.3. 范围 (Scope)

**包含的核心功能**）：

| 模块 | 通道 | 拦截技术
|------|------|---------|
| VFS 反勒索模块 | SMB | Samba VFS 回调 (gf_openat 等) |
| 策略守护进程 | 全部 | epoll (VFS socket + fanotify fd)|
| FTP 反勒索模块 | FTP | fanotify FAN_OPEN_PERM + /proc/PID 上下文关联 |
| 云连携反勒索模块 | Google Drive / OneDrive | fanotify FAN_OPEN_PERM + rclone cmdline 解析 |
| 本地反勒索模块 | 本地进程 | fanotify FAN_OPEN_PERM + PID/comm 粒度 |
| 文件恢复工具 | 全部 | gfrguard-recover CLI |
| 规则升级工具 | 全部 | gfrguard-rule-update CLI（签名校验 + 原子替换 + SIGHUP 热生效） |
| 配置系统 | 全部 | JSON + SIGHUP 热重载 + 四通道子开关 |

---

## 2. 用户故事与场景 (User Stories & Scenarios)

### 2.1. 用户画像 (Persona)

| 角色 | 描述 | 核心关注点 |
|------|------|-----------|
| **IT 系统管理员** | 管理企业 NAS/Samba 文件服务器的运维人员 | 部署简便、不破坏现有服务、清晰的日志和告警 |
| **安全运维工程师** | 负责企业安全策略和事件响应的安全人员 | 检测准确率、误报率可控、阻断后可恢复、新威胁快速响应 |
| **开发/测试工程师** | 构建和验证 GFRGuard 功能的工程人员 | 配置灵活、调试信息充分、可复现的测试框架 |

### 2.2. 用户故事 (User Stories)

**故事一：勒索软件批量加密检测与阻断（SMB 通道）**
> 作为一个 IT 系统管理员，当 Windows 客户端被勒索软件感染并通过 SMB 向 NAS 写入加密文件时，我希望系统能自动检测到异常行为（高熵值、批量重命名为勒索扩展名、写入赎金信），并及时阻断该客户端会话并自动恢复被篡改的文件。

**故事二：正常业务操作不受影响**
> 作为一个 IT 系统管理员，当用户批量部署配置文件或更新软件包（相同内容覆盖多个目录）时，我希望系统能识别这是正常操作而非勒索行为，不触发阻断。

**故事三：配置策略灵活调整**
> 作为一个安全运维工程师，当业务环境发生变化时，我希望能通过修改 JSON 配置文件并发送 SIGHUP 信号来热重载所有策略参数，而不需要重启任何服务。

**故事四：文件被勒索后快速恢复**
> 作为一个 IT 系统管理员，当系统检测到勒索行为并自动阻断会话后，我希望能通过简单的命令从备份区恢复被篡改的文件，并同时清理勒索软件创建的加密文件和赎金信。

**故事五：多通道统一防护**
> 作为一个安全运维工程师，当企业同时使用 SMB 共享、云同步（Google Drive / OneDrive）和 FTP 三种文件访问方式时，我希望系统能在所有通道上提供一致的勒索行为检测和阻断能力，以便消除任一通道的防护盲区。

**故事七：按需启用防护通道**
> 作为一个安全运维工程师，我希望能通过配置总开关统一控制防护策略的启停，并可独立开关各通道（SMB / 云连携 / FTP / 本地），关闭不需要的通道以减少系统资源开销。

**故事八：保护范围精准控制**
> 作为一个安全运维工程师，我希望能指定保护的文件类型和例外文件/文件夹列表，使系统仅对真正重要的文件进行监控和备份。

**故事九：NAS 本地进程勒索行为检测**
> 作为一个安全运维工程师，当 NAS 上运行的某个进程（如备份脚本被篡改、第三方服务被植入恶意代码）直接在本地文件系统上执行批量加密或删除操作时，我希望系统能检测到该进程的异常行为（按 PID/进程名粒度追踪），并及时暂停或终止该进程。

**故事十：FTP 文件传输勒索检测**
> 作为一个安全运维工程师，当攻击者通过 FTP 协议向 NAS 上传加密文件或批量覆盖已有文件时，我希望系统能像 SMB 通道一样自动检测异常并阻断该 FTP 会话。

**故事十一：云同步加密文件传播阻断**
> 作为一个安全运维工程师，当客户端被勒索软件感染后加密文件通过云同步（如 OneDrive）扩散到 GF2000 设备时，我希望系统能检测到同步任务中的异常文件变更，并自动暂停该同步定时任务，防止加密文件进一步扩散。

---

## 3. 功能性需求 (Functional Requirements)

### 3.1. VFS 反勒索模块（SMB 通道）

**FR-VFS-01: SMB 文件操作实时监控**
- **描述**：系统应能够实时拦截 SMB 协议层面的关键文件操作，包括文件打开、写入、截断、重命名、删除和创建目录。
- **核心规则**：
  - 操作拦截对 SMB 客户端透明，不影响正常的文件 I/O 流程
  - 当检测到会话已被阻断时，拒绝后续文件操作并返回访问拒绝 (EACCES)
  - 发生错误时静默回退到正常的文件操作路径，不影响 Samba 服务稳定性
  - 排除 O_APPEND 模式（内核强制追加写入，非勒索攻击向量）
  - 覆盖 ftruncate 绕过防御（O_APPEND open + ftruncate 截断）

**FR-VFS-02: 固定前像保护**
- **描述**：对受保护用户共享中的既有文件，发生覆盖写（O_WRONLY|O_TRUNC）或 truncate 等破坏性写入时，统一创建修改前副本（前像），不依据文件重要性、进程恶意性或当前会话风险分选择是否备份。保护范围仅限配置指定的用户共享，OS 关键目录不纳入。
- **核心规则**：
  - 触发条件：文件被覆盖写入（O_WRONLY|O_TRUNC）、截断或删除时——按写入类型统一创建前像
  - 备份去重：通过 ctime 判断 30s 窗口内是否已备份
  - 备份流程：优先 reflink（FICLONE CoW 克隆，秒级零空间；需备份区与源同文件系统且支持 reflink，如 XFS reflink=1/btrfs）→ 文件系统不支持时回退 copy_file_range 内核零拷贝 → 再回退 read/write
  - 竞争保护：O_EXCL 创建备份文件，多线程并发安全
  - 备份失败时自动清理中间产物

**FR-VFS-03: 相同内容覆盖识别**
- **描述**：文件关闭时，通过 FNV-1a hash 比对新写入内容与备份内容，识别正常批量部署操作。
- **核心规则**：
  - 触发时机：gf_close()，仅对 is_risky 文件（含备份成功/失败/新建 RANSOM_EXT）
  - 内容相同时设 CONTENT_SAME 标记以抑制风险评分

**FR-VFS-04: 会话阻断检查**
- **描述**：在每个文件操作前，通过 stat mtime 缓存检查 blocked 文件，命中则返回 EACCES。

**FR-VFS-05: 文件操作事件上报**
- **描述**：通过 AF_UNIX SOCK_DGRAM 以 fire-and-forget 模式发送事件到 gfrguardd。
- **核心规则**：source_type 固定为 RGUARD_SOURCE_SMB，最多重试 3 次 (EAGAIN 间隔 500µs)

### 3.2. 策略守护进程（通用引擎）

**FR-DAEMON-01: 四通道事件接收与生命周期管理**
- **描述**：守护进程以 systemd 服务方式运行，通过两种机制接收四通道事件：
  - **SMB 通道**：Unix Socket DGRAM 接收 VFS 模块上报
  - **FTP / 云连携 / 本地通道**：共用 fanotify fd（FAN_CLASS_CONTENT），内核同步阻塞文件 open 操作
- **核心规则**：
  - epoll 单线程事件驱动 (socket + fanotify_fd + timerfd + signal)
  - fanotify 事件按路径前缀分发到对应 handler
  - SIGHUP 热重载，SIGTERM/SIGINT 优雅退出
  - 异常退出后 systemd 自动重启

**FR-DAEMON-02: 会话级行为追踪（统一 session key 格式）**
- **描述**：按通道维护会话级行为计数器。session key 格式全通道统一为 `username@client_ip`，由公共骨架（rguard_make_session_key）在通道 resolve 之后统一推导——通道只负责填充 username / client_ip 两个字段，不各自拼 key。各通道字段语义：
  - SMB：`user@ip`（VFS 上报真实会话用户与客户端 IP）
  - FTP：`user@ip`（三级上下文解析；全部失败时回退 `ftp@unknown`）
  - 云连携：`cloud@<task_name>`（client_ip 字段携带 rclone task_name；非 IP 格式被 inet_pton 闸门挡住，不会写入 blocked 文件）
  - 本地：`<comm>@local:<pid>:<starttime>`（client_ip 字段携带进程实例标识，starttime 防 PID 复用后会话串号）
- **核心规则**：
  - 1024 槽哈希表（FNV-1a + 线性探测）四通道共存，key 由骨架统一推导，通道间靠字段内容天然隔离，辅以 source_type 路由
  - 双窗口机制：短窗口(10s)重置操作计数器，长窗口(30s)重置会话整体状态；云连携通道独立窗口（默认 60s/180s）适配云 API 事件节奏
  - 追踪 11 项指标：modified / rename / delete / touched_dirs / ext_change / ransom_ext / high_entropy / rule_match / content_same / risk_score / risk_level

**FR-DAEMON-03: 内容信号分析**
- **描述**：对内容进行 Shannon 熵采样和 YARA 规则匹配，结果作为会话级证据参与行为风险评分。不逐文件标记 damaged/corrupted/encrypted 状态，不累计"损坏/加密文件数"，不按"某类文件数量≥N"的方式阻断（专利规避边界详见 FR-CONSTRAINT-03）。
- **核心规则**：
  - 触发时机：熵分析在写入过程中采样（SMB=OPEN/WRITE/TRUNCATE，fanotify=CREATE/MODIFY，采样文件头 8 KiB）；YARA 规则匹配在文件句柄关闭后执行（SMB=CLOSE，fanotify=CLOSE_WRITE），全文件扫描需要完整内容
  - 会话去重：同一会话首次命中某内容信号后，该会话后续文件不再执行对应扫描；窗口重置清空命中状态后扫描自动恢复
  - 评分语义：高熵为会话级布尔信号，首次命中置位、固定权重只加一次；YARA 为定性证据，任一命中直接把会话提升至 CRITICAL，不参与加权求和

**FR-DAEMON-04: 内容规则匹配**
- **描述**：对写入内容执行自有规则扫描，识别赎金信文本和加密文件结构。
- **核心规则**：
  - 规则集递归加载、容错编译、10s 超时、首条命中后该会话中止后续扫描

**FR-DAEMON-05: 加权风险评分**
- **描述**：多维加权评分 (0-100)，三级阈值 (warn=30 / high=60 / critical=80)。评分以文件操作行为指标为主，内容信号为辅，不基于"损坏文件数"或"加密文件数"驱动阻断。

**FR-DAEMON-06: 会话阻断执行**
- **描述**：CRITICAL 时根据 source_type 执行差异化的阻断动作。
- **核心规则**：

| 通道 | 阻断方式 |
|------|---------|
| SMB | 写 blocked 文件 + smbcontrol smbd close-share |
| FTP | FAN_DENY + kill vsftpd child (SIGTERM) + 写 blocked 文件 |
| 云连携 | FAN_DENY + neo-croner delete --task-name + kill 进程树 + 保存配置到 DB |
| 本地 | FAN_DENY + SIGKILL |

**FR-DAEMON-07: 文件自动恢复**
- **描述**：阻断后 fork 子进程 exec gfrguard-recover 恢复文件。
- **恢复方式**：SMB/FTP/本地通道 → 从 backup 区还原；云连携 → 文件恢复 + neo-croner add

**FR-DAEMON-08: 勒索扩展名检测**
- **描述**：在 RENAME 和 NEW_FILE 事件中检测已知勒索扩展名。

**FR-DAEMON-09: 存储空间管理**
- **描述**：60s 定时器检查备份存储区，超 80% 阈值清理 30 天前的已恢复备份。

**FR-DAEMON-10: 白名单与黑名单管理**
- **描述**：白名单支持 user/IP（CIDR/范围）+ 本地进程名白名单（`whitelist_comm`）；黑名单支持精确匹配 + CIDR/范围 + auto_add 标记。auto 加入的 IP 以 `{"ip", "auto_add": true}` 对象形式即时持久化到 rguard-policy.json（与手动条目同一列表，按 auto_add 区分），SIGHUP 热重载和 daemon 重启均不丢失，仅管理员显式删除可解除。

### 3.3. FTP 反勒索模块

**FR-FTP-01: FTP 文件操作同步拦截**
- **描述**：通过 fanotify FAN_OPEN_PERM 在内核层同步阻塞 vsftpd 子进程的 open() 操作，在文件被覆盖前完成备份和风险判定。
- **核心规则**：
  - 监控范围：rguard-policy.json 中 ftp.monitor_paths 配置的 FTP 目录，**递归覆盖整棵目录树**（nftw 逐目录 mark；新建/移入目录动态补 mark）
  - 拦截操作：覆盖写入（STOR/APPE → O_WRONLY|O_TRUNC）、新建文件（O_CREAT）
  - 检测操作（notify 异步事件，FAN_REPORT_DFID_NAME group，与 SMB VFS 通道对齐）：
    - 覆盖写/截断：FAN_MODIFY → WRITE|RISKY（truncate 经 ATTR_SIZE→FS_MODIFY 同样覆盖）
    - 新建文件/目录（mkdir）：FAN_CREATE → OPEN|NEW_FILE（勒索后缀检查 + created_files 追踪）
    - 删除：FAN_DELETE → DELETE
    - 重命名：FAN_RENAME→ RENAME（携带 new_name，支持 EXT_CHANGE/RANSOM_EXT 检测）
    - 关闭：FAN_CLOSE_WRITE → CLOSE（YARA入口）
  - 固有限制（fanotify 能力边界）：delete/rename/mkdir 无 perm 事件，仅能事后检测+阻断；unlink 不经 open，无删除前备份
  - 上下文关联（三级策略）：① `/proc/PID/cmdline` 直接提取 IP+User；② socket-inode 映射获取 IP；③ `/proc/PID/status` → UID → getpwuid 获取 User
    - 支持本地用户、匿名用户、虚拟用户（通过 cmdline 解析）
  - 无需 PID 表——fanotify FAN_OPEN_PERM 同步阻塞进程，/proc 解析在事件处理时完成
- **优先级**：P0

**FR-FTP-02: FTP 场景风险阻断**
- **描述**：CRITICAL 时 FAN_DENY 拒绝当前操作 + SIGTERM 终止 vsftpd 子进程 + 写 blocked 文件。
- **核心规则**：
  - 阻断与 SMB 通道互通（同一 user@ip 在两个通道间共享阻断状态）
  - vsftpd 子进程终止后，客户端后续 FTP 命令无法执行
- **优先级**：P0

**FR-FTP-03: FTP 场景文件保护与恢复**
- **描述**：从 fanotify 事件 fd 备份（目标进程被内核阻塞，文件内容未变）：优先 reflink（FICLONE），文件系统不支持时回退 copy_file_range，再回退 read/write（与 FR-VFS-02 同一策略，共享 rguard_backup.h 实现）。
- **恢复**：复用 gfrguard-recover restore，从同一备份区还原
- **优先级**：P0

### 3.4. 云连携反勒索模块

**FR-CLOUD-01: 云同步文件操作同步拦截**
- **描述**：通过 fanotify FAN_OPEN_PERM 在内核层同步阻塞 rclone 进程的 open() 操作。
- **核心规则**：
  - 监控范围：rguard-policy.json 中 cloud_sync.tasks[].local_path 配置的 rclone 本地目录
  - 任务识别：解析 rclone 进程的 /proc/PID/cmdline，找到 `remote:path` 格式参数，取 `:` 前部分作为 task_name
  - session_key = `cloud@<task_name>`（如 `cloud@onedrive_1`）
  - 排除 rclone 临时文件（`.partial~`、`.tmp`、`.rclone-tmp`）
- **优先级**：P0

**FR-CLOUD-02: 云同步任务阻断**
- **描述**：CRITICAL 时 FAN_DENY + kill rclone 进程树 + neo-croner delete --task-name 删除定时任务。
- **核心规则**：
  - 阻断前通过 neo-croner query 保存任务配置（expression + command）到 DB
  - 删除定时任务防止 neo-croner 自动重启同步
  - session 独立于 SMB/FTP（key 格式 `cloud@<task_name>`，不写 blocked 文件）
- **优先级**：P0

**FR-CLOUD-03: 云同步任务恢复**
- **描述**：恢复时从 DB 读取保存的任务配置，通过 neo-croner add 重新注册定时任务。
- **核心规则**：
  - 命令：`gfrguard-recover cloud-restore --task-name <NAME>`
  - 步骤：从备份区恢复文件 + neo-croner add --task-name ... --expression ... --command ...
- **优先级**：P1

### 3.5. 本地反勒索模块

**FR-LOCAL-01: NAS 本地进程文件操作同步拦截**
- **描述**：通过 fanotify FAN_OPEN_PERM 监控受保护目录下所有进程的文件操作，以 PID 为粒度追踪。
- **核心规则**：
  - 监控范围：rguard-policy.json 中 local.monitor_paths 配置的本地目录，**递归覆盖整棵目录树**（同 FR-FTP-01）
  - 检测事件覆盖与 FTP 通道一致（见 FR-FTP-01）：MODIFY / CREATE（含 mkdir）/ DELETE / RENAME / CLOSE_WRITE
  - session_key = `<comm>@local:<pid>:<starttime>`（统一 `username@client_ip` 格式：comm 填 username 字段，`local:<pid>:<starttime>` 填 client_ip 字段），starttime 取自 `/proc/PID/stat` 防 PID 复用
  - 进程名白名单（smbd / systemd / sshd / rclone / vsftpd / gfrguardd 等）→ FAN_ALLOW 直接放行
  - 白名单进程跳过所有检测和评分，不做备份
- **优先级**：P0

**FR-LOCAL-02: 本地恶意进程阻断**
- **描述**：CRITICAL 时 FAN_DENY + SIGKILL
- **优先级**：P0

**FR-LOCAL-03: 本地进程行为检测适配**
- **描述**：复用 daemon 评分引擎，增加本地专用规则：
  - 随机字符串进程名（长度≥8 且无元音或全 hex）→ risk_score +20
  - 相同 comm 的 ≥3 个 PID 同时触发 → 直接提升到 critical
- **核心规则**：评分阈值 critical=75（略低于 SMB 的 80，本地批量操作更快）
- **优先级**：P1

### 3.6. 文件恢复工具

**FR-RECOVER-01: 手动文件恢复**
- **描述**：命令行工具 gfrguard-recover，支持 restore / unblock / cloud-restore 子命令。
- **恢复范围**：SMB/FTP/本地 → restore --event <id> --auto；云连携 → cloud-restore --task-name <NAME>

### 3.7. 配置系统

**FR-CONFIG-01: JSON 配置管理**
- **描述**：全局唯一配置，方便管理：
  - rguard-policy.json：全通道顶层策略 + protection 开关 + ftp/cloud_sync/local 模块配置 + whitelist/blacklist/exceptions/file_extensions
- **核心规则**：所有参数均有默认值，最小配置即可运行（仅需配置 fanotify 监控路径）

**FR-CONFIG-02: 配置热重载**
- **描述**：SIGHUP → daemon 全量重读配置

**FR-CONFIG-03: 反勒索防护总开关与子通道开关**
- **描述**：protection.enabled（总开关）+ protection.{smb, cloud_sync, ftp, host}（四个子通道开关），默认全部开启，SIGHUP 热重载。

**FR-CONFIG-04: 保护文件类型配置**
- **描述**：file_extensions.all（默认 true 保护所有）+ manual 扩展名列表（all=false 时仅保护指定类型）。

**FR-CONFIG-05: 例外文件/文件夹与进程白名单**
- **描述**：exceptions.files/folders 跳过指定路径 + local.whitelist_comm 跳过指定进程。

### 3.8. 自有内容检测规则集

**FR-RULE-01: 赎金信内容检测**
- **描述**：规则覆盖赎金信关键短语、文件名模式、暗网链接、加密货币钱包地址、数据泄露威胁。

**FR-RULE-02: 加密文件结构检测**
- **描述**：规则覆盖已知勒索软件家族的加密文件头部标识、嵌入的 RSA/PEM 密钥材料。

**FR-RULE-03: 签名规则升级**
- **描述**：提供独立升级工具 `gfrguard-rule-update`（按需执行，不常驻），支持从离线规则包或在线升级服务器获取新版全量规则，安全替换现有规则集并热生效。
- **核心规则**：
  - 完整性校验：签名校验 + 哈希校验，校验失败则报错退出，现有规则不变
  - 原子替换：目录级 rename 替换 `/etc/gf2000/yara-rules/`，daemon 任意时刻要么看到完整旧规则、要么看到完整新规则
  - 热生效：替换后向 gfrguardd 发送 SIGHUP 触发 `yara_engine_reload`；reload 失败回退旧规则并记录日志，升级事故不影响检测主路径
  - 复用既有 SIGHUP 热重载通道，不新增 IPC 机制

---

## 4. 技术约束

**FR-CONSTRAINT-01: 保护范围**

GFRGuard 仅保护经由明确配置的 SMB 共享、FTP 目录、云同步目录及本地监控目录暴露的**对外用户共享数据**。以下目录和对象**不在保护范围内**，不纳入前像保护和事件监控：

- 操作系统启动文件（`/boot`）
- 系统配置文件（`/etc`，Samba 核心配置除外）
- 系统可执行文件（`/bin /sbin /usr/bin /usr/sbin`）
- 系统动态库（`/lib /usr/lib /lib64 /usr/lib64`）
- 系统数据库和启动配置
- GF2000 系统程序和关键服务文件

**FR-CONSTRAINT-02: 固定前像**

对受保护用户共享中的既有文件，覆盖写和 truncate 等破坏性写操作**依照写入类型统一创建前像**。前像生成逻辑不依据文件重要性、进程可信度/恶意性或当前会话风险评分选择性触发。前像保护与后续的反勒索会话评分在代码模块和数据流上解耦。

**FR-CONSTRAINT-03: 内容信号与计分规则**

内容信号定位与计分方式共同构成专利规避边界，二者不可拆分：

- **触发时机**：熵分析在写入过程中采样（文件头 8 KiB）；YARA 规则匹配在文件句柄关闭后触发（CLOSE / CLOSE_WRITE，全文件扫描需要完整内容）；
- **不计数、不判定**：系统不逐文件标记 damaged/corrupted/encrypted 状态，不累计"损坏文件数量"，不按"损坏文件数≥N"触发阻断。高熵为会话级布尔信号——首次命中置位、固定权重只加一次；YARA 为定性证据——任一命中直接把会话提升至 CRITICAL，不参与加权求和；
- **会话级去重**：同一会话首次命中某内容信号后，该会话后续文件不再执行对应扫描；窗口重置清空命中状态后扫描自动恢复；
- **阻断多维性**：任何单一行为计数维度（修改 / 重命名 / 删除 / 目录扩散）的加权贡献不得单独达到 CRITICAL；CRITICAL 必须由至少两个独立行为维度、或维度评分叠加定性证据（YARA / 勒索扩展名）共同达到。
