# LLM-Linux-1
软件质量保障-LLM辅助Linux内核缺陷静态检测-第一组

judge_engine.py：基于LLM的静态分析缺陷二次判定引擎，用于区分真实漏洞与误报。
judge_output.json：使用上述引擎对示例缺陷数据判定的输出结果报告。

---

## 规则预处理层（我们负责部分）交付说明

### 核心代码

Knighter/src/a_rule_triage.py：规则层核心逻辑（格式归一化、去重、规则过滤、统计分析、补全 code_context、导出 JSONL）。
Knighter/scripts/a_rule_triage.py：规则层命令行入口（triage / enrich_code_context / export_for_llm）。
Knighter/scripts/cppcheck_xml_to_findings.py：将 cppcheck 的 XML 报告转换为统一 findings JSON 格式。
Knighter/scripts/run_a_pipeline.py：一键流水线脚本（cppcheck → findings → triage → 补上下文 → 导出 JSONL）。
Knighter/scripts/a_ruleset.cppcheck_focus.json：默认降噪规则集（过滤 style/unused 等噪声告警）。
Knighter/scripts/a_ruleset.example.json：规则集配置示例（可按项目自定义）。
Knighter/scripts/make_sample_target.py：生成示例目标代码（用于本地复现与演示）。

### 示例数据与产物

code/sample_target/：示例 C 目标代码目录，用于本地跑通 cppcheck 与 code_context 补全。
for_llm.cppcheck.with_ctx.v2.jsonl：提供给后续 LLM 判定的稳定 JSONL 输入（含 code_context）。
triage_cppcheck.with_ctx.v2.json：规则层分析报告（含 summary、analysis 统计与典型样例）。

### 不建议提交（可本地重新生成）

cppcheck.xml、cppcheck_findings.json、triage_cppcheck.json 等中间文件（体积大、可复现，不必入库）。
final_report.json（融合阶段产物，非本模块单独交付）。
Knighter/ 下与规则层无关的大体积依赖目录（如 tree-sitter-cpp 等），除非老师要求整包上传。

---

## 一键复现（本地验证后再提交）

```powershell
python "Knighter\scripts\run_a_pipeline.py" `
  --workspace_root "C:\Users\11452\Desktop\software quality assurance" `
  --cppcheck_exe "E:\cppcheck.exe"
```

运行成功后，根目录应生成/更新：`cppcheck.xml`、`cppcheck_findings.json`、`triage_cppcheck.with_ctx.json`、`for_llm.cppcheck.with_ctx.jsonl`。
提交 GitHub 时建议只保留 **v2 最终产物**（见上方「示例数据与产物」）。

---

## GitHub 提交步骤（复制即用）

**团队仓库：** https://github.com/RyilEuu/LLM-Linux-1  
**默认分支：** `main`  
**本地工作目录：** `C:\Users\11452\Desktop\software quality assurance`  
**克隆后仓库目录：** `C:\Users\11452\Desktop\LLM-Linux-1`

以下命令在 **PowerShell** 中逐条复制执行即可。

---

### 第一步：克隆团队仓库（只需做一次）

```powershell
cd "C:\Users\11452\Desktop"
git clone https://github.com/RyilEuu/LLM-Linux-1.git
cd "C:\Users\11452\Desktop\LLM-Linux-1"
```

---

### 第二步：把我们要提交的文件复制进仓库（每次更新后执行）

```powershell
$src = "C:\Users\11452\Desktop\software quality assurance"
$dst = "C:\Users\11452\Desktop\LLM-Linux-1"

New-Item -ItemType Directory -Force -Path "$dst\Knighter\src", "$dst\Knighter\scripts", "$dst\code" | Out-Null

Copy-Item "$src\README.md" "$dst\README.md" -Force
Copy-Item "$src\Knighter\src\a_rule_triage.py" "$dst\Knighter\src\a_rule_triage.py" -Force
Copy-Item "$src\Knighter\scripts\a_rule_triage.py" "$dst\Knighter\scripts\a_rule_triage.py" -Force
Copy-Item "$src\Knighter\scripts\cppcheck_xml_to_findings.py" "$dst\Knighter\scripts\cppcheck_xml_to_findings.py" -Force
Copy-Item "$src\Knighter\scripts\run_a_pipeline.py" "$dst\Knighter\scripts\run_a_pipeline.py" -Force
Copy-Item "$src\Knighter\scripts\a_ruleset.cppcheck_focus.json" "$dst\Knighter\scripts\a_ruleset.cppcheck_focus.json" -Force
Copy-Item "$src\Knighter\scripts\a_ruleset.example.json" "$dst\Knighter\scripts\a_ruleset.example.json" -Force
Copy-Item "$src\Knighter\scripts\make_sample_target.py" "$dst\Knighter\scripts\make_sample_target.py" -Force
Copy-Item "$src\code\sample_target" "$dst\code\sample_target" -Recurse -Force
Copy-Item "$src\for_llm.cppcheck.with_ctx.v2.jsonl" "$dst\for_llm.cppcheck.with_ctx.v2.jsonl" -Force
Copy-Item "$src\triage_cppcheck.with_ctx.v2.json" "$dst\triage_cppcheck.with_ctx.v2.json" -Force
```

复制完成后，仓库里应保留组员已有的 `judge_engine.py`、`judge_output.json`，并新增我们上面的文件。

---

### 第三步：进入仓库，确认分支

```powershell
cd "C:\Users\11452\Desktop\LLM-Linux-1"
git status
git branch
```

---

### 第四步：只添加我们需要提交的文件

```powershell
git add README.md
git add Knighter/src/a_rule_triage.py
git add Knighter/scripts/a_rule_triage.py
git add Knighter/scripts/cppcheck_xml_to_findings.py
git add Knighter/scripts/run_a_pipeline.py
git add Knighter/scripts/a_ruleset.cppcheck_focus.json
git add Knighter/scripts/a_ruleset.example.json
git add Knighter/scripts/make_sample_target.py
git add code/sample_target/
git add for_llm.cppcheck.with_ctx.v2.jsonl
git add triage_cppcheck.with_ctx.v2.json
```

---

### 第五步：再次确认暂存区

```powershell
git status
```

应看到新增/修改的文件都在 **Changes to be committed** 里；不应出现 `cppcheck.xml`、`final_report.json`、`Knighter/src/kparser/` 等无关大文件。

---

### 第六步：提交

```powershell
git commit -m "feat(rule-layer): 完成规则预处理层与LLM输入导出" -m "- 实现 cppcheck XML 到统一 findings 的解析" -m "- 实现规则层去重、降噪过滤、统计分析与 code_context 补全" -m "- 导出稳定 JSONL 输入 for_llm.cppcheck.with_ctx.v2.jsonl" -m "- 提供一键脚本 run_a_pipeline.py 与示例代码 sample_target" -m "- 更新 README 说明交付物与复现步骤"
```

---

### 第七步：推送到 GitHub

```powershell
git push origin main
```

推送成功后，打开 https://github.com/RyilEuu/LLM-Linux-1 即可看到新文件。

---

### 若 push 失败：先拉再推

```powershell
git pull origin main
git push origin main
```

---

### 若提示需要登录 GitHub

第一次 push 时，Windows 可能弹出浏览器让你登录 GitHub 账号（需有该仓库的写入权限）。  
若没有权限，请联系仓库管理员 `RyilEuu` 把你加入 Collaborator。

---

## Commit 说明参考（给老师/组员看）

本次提交完成：**静态分析规则预处理层**。主要工作包括：将 cppcheck 输出统一为 findings 格式；通过规则集过滤噪声告警；对保留告警补全代码上下文；输出 triage 分析报告与供 LLM 使用的 JSONL 契约文件；并提供可复现的一键脚本与示例目标代码。
