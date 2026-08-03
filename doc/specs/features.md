# AR 特性列表

按管理界面页面组织（对应 demo 原型）的**特性索引**。

本文档不定义行为语义：所有规则、默认值、容量上限的唯一事实源是 [requirements.md](requirements.md) 中的 FR 条目。本表只列出页面特性及其实现状态，并引用定义它的 FR；修改语义时只改 FR 条目，本表引用自动生效。

状态标记：✅ 已实现 ｜ 📋 已规划待实现 ｜ ⚠️ 需求未确认

## 1. 许可管理

| 特性 | 需求引用 |
| --- | --- |
| 📋 许可激活（自动获取 license） | FR-LICENSE-01 |
| 📋 许可激活（手动输入 license） | FR-LICENSE-01 |
| 📋 许可状态（激活状态与有效期展示） | FR-LICENSE-01 |
| 📋 无有效 license 时勒索软件检查开关禁用 | FR-LICENSE-01 |

## 2. 基本设置

| 特性 | 需求引用 |
| --- | --- |
| ✅ 勒索攻击防御总开关 | FR-BASIC-CONFIG-01 |
| ✅ 四通道子开关（本地 / SMB / 云连携 / FTP） | FR-BASIC-CONFIG-01 |
| ✅ 发现勒索病毒后动作（自动恢复 / 手动恢复） | FR-BASIC-CONFIG-02 |
| ✅ 保护文件类型 | FR-BASIC-CONFIG-03 |
| 📋 引擎版本展示与更新 | FR-BASIC-CONFIG-05, FR-ENGINE-UPDATE-01 |
| 📋 规则库版本展示与更新 | FR-BASIC-CONFIG-05, FR-BASIC-CONFIG-08 |

## 3. 隔离区设置

| 特性 | 需求引用 |
| --- | --- |
| ⚠️ 隔离区路径 | FR-QUAR-STORE-01 |
| 📋 隔离区容量配置 | FR-QUAR-STORE-02, FR-STORE-01 |
| 📋 隔离区写满策略 | FR-QUAR-STORE-03, FR-LIMIT-03 |
| 📋 使用情况展示 | FR-QUAR-STORE-04 |
| 📋 清空隔离区 | FR-QUAR-STORE-05 |
| 📋 释放隔离区磁盘空间 | FR-QUAR-STORE-06 |

## 4. 安全备份区设置

| 特性 | 需求引用 |
| --- | --- |
| ⚠️ 备份区路径 | FR-BACKUP-STORE-01 |
| 📋 备份区容量配置 | FR-BACKUP-STORE-02, FR-STORE-01 |
| 📋 单文件备份大小限制 | FR-BACKUP-STORE-03, FR-LIMIT-05 |
| 📋 备份区写满策略 | FR-BACKUP-STORE-04, FR-LIMIT-01 |
| 📋 使用情况展示 | FR-BACKUP-STORE-02 |
| 📋 清空安全备份区 | FR-BACKUP-STORE-05 |
| 📋 释放安全备份区磁盘空间 | FR-BACKUP-STORE-06 |

## 5. 黑白名单

| 特性 | 需求引用 |
| --- | --- |
| ✅ IP 黑/白名单 | FR-BWLIST-01 |
| ✅ 用户黑/白名单 | FR-BWLIST-02 |
| ✅ 自动黑名单标记 | FR-BWLIST-01 |
| 📋 IP 名单导入/导出 | FR-BWLIST-01 |

## 6. 例外设置

| 特性 | 需求引用 |
| --- | --- |
| ✅ 例外文件 | FR-EXCEPTION-01 |
| ✅ 例外文件夹 | FR-EXCEPTION-02 |
| 📋 路径显示 | FR-COMMON-01 |

## 7. 事件记录

### 7.1 勒索检测日志

| 特性 | 需求引用 |
| --- | --- |
| ✅ 检测事件记录 | FR-EVENT-02, FR-EVENT-03 |
| ✅ 未处理/已处理分栏 | FR-EVENT-02, FR-EVENT-03 |
| 📋 事件筛选与清除 | FR-EVENT-02, FR-EVENT-03 |
| ✅ 事件级恢复 | FR-EVENT-02, FR-EVENT-06 |
| 📋 文件详情 | FR-EVENT-02, FR-EVENT-03 |
| 📋 路径显示 | FR-COMMON-01 |
| 📋 导出 CSV | FR-EVENT-02, FR-EVENT-03 |

### 7.2 隔离区

| 特性 | 需求引用 |
| --- | --- |
| 📋 隔离事件列表 | FR-EVENT-04 |
| 📋 从隔离区恢复 / 删除 | FR-EVENT-04 |
| 📋 隔离文件详情 | FR-EVENT-04 |
| 📋 路径显示 | FR-COMMON-01 |

### 7.3 阻断链接

| 特性 | 需求引用 |
| --- | --- |
| ✅ 阻断会话记录 | FR-EVENT-01 |
| ✅ 解除阻断 | FR-EVENT-01 |
| 📋 筛选与导出 CSV | FR-EVENT-01 |

### 7.4 告警

| 特性 | 需求引用 |
| --- | --- |
| 📋 系统日志 | FR-EVENT-05 |
| 📋 邮件告警 | FR-BASIC-CONFIG-04 |

***

## 8. 边界与容量限制

容量上限与写满行为的唯一事实源为 requirements.md §3.11（FR-LIMIT-01 ~ FR-LIMIT-11），本节仅为实现状态索引。

| 特性 | 需求引用 |
| --- | --- |
| 📋 备份区写满策略 | FR-LIMIT-01 |
| 📋 备份区大小策略 | FR-LIMIT-02 |
| 📋 隔离区写满策略 | FR-LIMIT-03 |
| 📋 隔离区大小策略 | FR-LIMIT-04 |
| ✅ IP 黑名单容量 | FR-LIMIT-06 |
| ✅ IP 白名单容量 | FR-LIMIT-06 |
| ✅ 用户黑/白名单容量 | FR-LIMIT-06 |
| ✅ 例外路径长度上限 | FR-LIMIT-08 |
| 📋 阻断事件显示上限 | FR-LIMIT-09 |
| 📋 勒索事件显示上限与 CSV 归档 | FR-LIMIT-10 |
| 📋 隔离事件显示上限与 CSV 归档 | FR-LIMIT-11 |
