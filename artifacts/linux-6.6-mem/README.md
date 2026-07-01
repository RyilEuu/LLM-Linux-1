# 补充实验：Linux 6.6 真实内核文件

## 实验对象
- **内核版本**：Linux **6.6**（LTS 主线）
- **模块/文件**：`drivers/char/mem.c`（字符设备 `/dev/mem` 相关驱动）
- **源码路径**：`code/linux-kernel/drivers/char/mem.c`
- **静态工具**：Cppcheck 2.21.0

## 运行命令
```powershell
python Knighter/scripts/run_a_pipeline.py ^
  --workspace_root "c:\Users\11452\Desktop\software quality assurance" ^
  --cppcheck_exe "C:\Program Files\Cppcheck\cppcheck.exe" ^
  --code_root "code/linux-kernel/drivers/char/mem.c" ^
  --platform unix64
```

## 结果（默认规则集 a_ruleset.cppcheck_focus.json）
| 阶段 | 数量 |
|------|------|
| cppcheck 原始告警 | **57**（去重后 54） |
| 规则层保留 | **23** |
| 规则层过滤 | **31** |

### 保留告警构成
- `missingIncludeSystem`：22（缺少内核头文件 `<linux/*.h>`，单文件扫描预期现象）
- `staticFunction`：1（style 类建议）

### 说明（答辩口述）
单文件扫描 **未配置内核 include 路径与 .config**，cppcheck 无法做完整语义分析，因此告警以「缺头文件」为主，**不代表 mem.c 无安全缺陷**。本补充实验用于证明：
1. 流水线可直接接入 **真实 Linux 内核源码文件**；
2. 完整内核扫描需后续接入 **内核编译数据库 / 头文件路径**（工程化改进方向）。

## 产物
- `artifacts/linux-6.6-mem/cppcheck_findings.json`
- `artifacts/linux-6.6-mem/triage_cppcheck.with_ctx.json`
- `artifacts/linux-6.6-mem/for_llm.cppcheck.with_ctx.jsonl`

主实验（sample_target 32→7）备份在 `artifacts/sample_target/`。
