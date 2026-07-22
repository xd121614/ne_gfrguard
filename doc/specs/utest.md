# GFRGuard 单元测试与自动化测试

本文档描述当前 `tests/` 目录中的可执行测试，不记录历史运行结果、规则修订过程或样本研究记录。

## 1. 测试分层

| 层级 | 测试内容 | 运行环境 | 入口 |
|---|---|---|---|
| L0 编译期检查 | IPC 结构大小、字段偏移和常量约束 | C17 编译器 | 构建源码时自动执行 `_Static_assert` |
| L1 环境准备 | 安装依赖、构建产物、部署配置和测试共享 | Debian/Ubuntu 或 RHEL/AlmaLinux 系 | `bash tests/setup_l1_env.sh` |
| L2 单元测试 | common、daemon、recover 的可独立逻辑 | Linux 构建主机 | `cd tests && make -f Makefile.test` |
| L3 集成测试 | SMB、FTP、Cloud、Local 四通道端到端行为 | root、Samba、fanotify、YARA、SQLite | `bash tests/integration/run_all.sh` |

L1 是环境初始化步骤。L2 可重复执行；L3 会修改测试策略、运行目录、Samba 配置和测试文件，只能在隔离测试设备或虚拟机中运行。

## 2. Layer 0：编译期检查

`src/common/rguard_protocol.h` 使用 `_Static_assert` 固定 `rguard_event_msg` 的 ABI，包括：

- 消息总大小为 4608 字节；
- `msg_type`、`flags`、时间和文件元数据字段偏移；
- `username`、`client_ip`、`share_name`、`file_path` 和 `new_name` 偏移；
- `source_type`、`proto_version` 和预留区布局；
- 操作码和标志位互不冲突。

任何布局变化都会在编译阶段失败。协议变更必须同步更新发送端、接收端和协议测试。

## 3. Layer 1：测试环境准备

```bash
bash tests/setup_l1_env.sh
```

脚本执行以下操作：

1. 识别 Debian/Ubuntu 或 RHEL/AlmaLinux 系发行版并安装构建依赖；
2. 查找或构建与目标版本匹配的 Samba 源码头文件；
3. 使用 CMake 构建 `gfrguardd`、`gfrguard-recover` 和可选的 `gfrguard.so`；
4. 执行 L2 单元测试；
5. 安装二进制、YARA 规则、JSON 配置和测试 Samba 共享；
6. 创建运行目录与 `testuser`。

可通过环境变量指定 Samba 版本和路径：

```bash
SAMBA_VER=4.19.6 \
SAMBA_SRC=./samba-src/samba-4.19.6 \
bash tests/setup_l1_env.sh
```

VFS 模块必须使用目标 Samba 版本的源码头文件构建。没有 Samba 源码时仍可运行 L2，但不能验证 SMB VFS 集成。

## 4. Layer 2：单元测试

### 4.1 运行方式

```bash
cd tests
make -f Makefile.test
```

当前 `Makefile.test` 构建并运行 18 个测试二进制：

| 测试 | 主要覆盖 |
|---|---|
| `test_protocol` | 消息大小、字段偏移、协议版本、标志和操作码 |
| `test_entropy` | Shannon 熵、空文件、错误路径、阈值和采样常量 |
| `test_session` | 会话哈希表、滑动窗口、行为计数和目录去重 |
| `test_scorer` | 权重、阈值、分数封顶、YARA 强制升级和 CONTENT_SAME 抑制 |
| `test_config` | 默认值、无效配置、外部/内联评分、名单和 Cloud 窗口 |
| `test_db` | schema、事件/前像/新建文件/Cloud 任务 CRUD、去重和序列号 |
| `test_blacklist` | 自动黑名单去重、手工条目保护和 FIFO 淘汰 |
| `test_fangate` | 首次放行、窗口抑制、碰撞 fail-open 和 reset |
| `test_backup` | 空文件、非对齐文件、多块复制和不可 seek 输入失败 |
| `test_blocker` | blocked 文件追加、去重、IP 校验、同步和解除阻断 |
| `test_space` | 存储路径、使用率阈值和清理错误路径 |
| `test_log` | 日志初始化、级别过滤、JSON 转义和注入防护 |
| `test_channels` | `/proc` 身份、进程白名单、FTP 地址解析、PID 复用和 neo-croner 超时 |
| `test_hash` | FNV 向量、排序查找、长度匹配和碰撞遍历 |
| `test_yara` | 规则加载、匹配、坏规则隔离、reload 和异常文件类型 |
| `test_restore` | 自动恢复开关、参数校验、fork/exec 和子进程回收 |
| `test_recover` | 路径校验、符号链接防护、隔离、恢复和新建文件清理 |
| `test_main_daemon` | `process_msg` 门控、评分升级、名单、事件入库和 Cloud 窗口 |

`Makefile.test` 是当前完整 L2 清单。CMake/CTest 只注册其中一部分基础测试，因此需要完整回归时应使用 `Makefile.test`。

### 4.2 测试原则

- 单元测试使用 `tests/test_main.h` 中的轻量断言框架；
- 临时文件和数据库写入 `/tmp`，测试必须自行清理或使用唯一名称；
- `test_restore` 将恢复程序替换为 `/bin/true`，只验证调度和回收，不替代真实恢复测试；
- `test_channels` 使用缩短的 neo-croner 超时，避免挂起测试进程；
- L2 不加载 Samba VFS，也不验证真实 fanotify 内核事件。

## 5. Layer 3：集成测试

### 5.1 运行方式

使用系统 Samba：

```bash
sudo bash tests/integration/run_all.sh
```

使用指定源码构建的 Samba：

```bash
sudo SAMBA_VER=4.19.6 \
  SAMBA_SRC_BASE=./samba-src \
  bash tests/integration/run_all.sh
```

依次验证仓库支持的 Samba 版本：

```bash
sudo bash tests/integration/run_all_versions.sh
```

`run_all_versions.sh` 当前依次尝试 Samba 4.23.5 和 4.19.6；缺少源码树或二进制不兼容时会跳过对应版本。

### 5.2 主集成套件

`run_all.sh` 当前包含 27 个编号场景：

| 场景 | 通道 | 验证内容 |
|---|---|---|
| 1-4 | SMB | 首次写前像、YARA、blocked 拒绝和事件恢复 |
| 5-7 | SMB | 文件/目录例外及非例外健全性 |
| 8-12 | SMB | IP/用户白名单、自动黑名单和手工黑名单 |
| 13-14 | FTP/Local | 黑名单 permission open 的 FAN_DENY 与进程动作 |
| 15-18 | FTP/Local | CLOSE_WRITE 后 YARA 与高熵检测 |
| 19-24 | Local | 递归 mark、MODIFY、动态目录、DELETE、MOVE 配对和洪泛门 |
| 25 | Local | SIGHUP 后重建 fanotify marks |
| 26 | Cloud | Cloud CLOSE_WRITE、YARA、CRITICAL 和任务阻断 |
| 27 | Cloud | 长窗口下慢速勒索扩展名行为评分 |

套件使用同一个 daemon 进程环境，并在场景之间重置策略、blocked 文件、数据库记录和前像目录。部分 FTP、Local 和 Cloud 场景依赖 Python 3；缺少 Python 3 时相关场景会跳过。

### 5.3 独立场景脚本

`tests/integration/test_01_*.sh` 至 `test_13_*.sh` 提供针对 SMB、FTP 和 Local 基础场景的独立调试入口，覆盖：

- 正常写和 CONTENT_SAME；
- 前像与恢复；
- 勒索行为模拟；
- YARA、blocked 和高熵；
- FTP/Local fanotify 阻断、YARA 和高熵。

完整回归以 `run_all.sh` 为准；独立脚本适合定位单一场景，不等同于 27 场景主套件。

## 6. 环境与限制

### 6.1 必要条件

- Linux root 或 `CAP_SYS_ADMIN`；
- 内核支持 fanotify permission 事件；FID 通知建议 Linux 5.9 及以上；
- Samba 客户端、服务端和版本匹配的 VFS 模块；
- SQLite3、YARA、Python 3 及常用 coreutils；
- 可写的 `/etc/gf2000`、`/run/gfrguardd`、`/var/lib/gf2000/rguard-store` 和日志目录。

### 6.2 已知限制

- WSL2 和受限容器通常不能运行 fanotify 集成测试，应使用 VM 或物理机；
- L3 会停止或重启 `smbd`、终止 `gfrguardd`、修改测试策略并清理测试前像，不得在生产设备运行；
- 测试策略使用 `permissive` 模式且关闭自动恢复，以便隔离各场景；
- fanotify 场景依赖 debug 日志中的事件字段，修改日志格式时必须同步测试；
- 超大目录树可能受 `fs.fanotify.max_user_marks` 限制；
- 集成脚本中的 SKIP 不计为失败，测试报告必须同时记录实际执行和跳过的场景。

## 7. 覆盖边界

当前测试覆盖主要控制流，但以下风险仍需要补充专项测试：

1. OS 关键目录不能被配置为保护根；
2. VFS DGRAM 发送方凭据校验和伪造事件拒绝；
3. 前像已创建但被策略门控跳过入库时的对账与恢复；
4. YARA 慢规则对 daemon 主循环和 permission 响应延迟的影响；
5. 同一事件或路径并发恢复的互斥；
6. Web 管理端与 daemon 对 blocked 文件格式的一致性；
7. Web 恢复必须复用 recover 的路径和符号链接安全检查；
8. 专利边界静态门禁：不得新增逐文件损坏状态或损坏文件数量阻断逻辑。

## 8. CI 建议

```yaml
stages: [build, unit, integration]

unit:
  stage: unit
  script:
    - cd tests
    - make -f Makefile.test

integration:
  stage: integration
  script:
    - bash tests/integration/run_all.sh
  tags: [linux, root, samba, fanotify]
  when: manual
```

CI 必须保存 L2 完整输出、L3 的 executed/skipped/failed 数量、daemon 日志和失败场景诊断信息。不能仅根据脚本退出码宣称所有 27 个场景均已执行。