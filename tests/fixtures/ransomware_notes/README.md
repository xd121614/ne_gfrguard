# Ransomware Ransom Notes — YARA TP Test Set

每个文件包含对应家族的真实赎金信文本（提取自己的公开安全报告）。

**来源**：
- CISA: https://www.cisa.gov/stopransomware
- BleepingComputer: https://www.bleepingcomputer.com/tag/ransomware/
- CrowdStrike: https://www.crowdstrike.com/blog/
- SentinelOne: https://www.sentinelone.com/blog/
- Hunt & Hackett: https://www.huntandhackett.com/blog/technical-curiosities-of-akira-ransomware
- ThreatDown (Malwarebytes): https://www.threatdown.com/blog/akira-ransomware-gang-who-they-are-and-how-to-prevent-infection/
- PCrisk: https://www.pcrisk.com/removal-guides/

**使用**：
```bash
yara -r files/yara-rules/ tests/fixtures/ransomware_notes/
```
