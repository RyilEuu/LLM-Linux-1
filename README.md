# LLM-Linux-1
软件质量保障-LLM辅助Linux内核缺陷静态检测-第一组

run.py：基于LLM的静态分析缺陷二次判定引擎，用于区分真实漏洞与误报。
llm_judgments.json：使用上述引擎对示例缺陷数据判定的输出结果报告。

Knighter/src/a_rule_triage.py：规则层核心逻辑，负责格式归一化、去重、规则过滤、统计分析、补全 code_context、导出 JSONL。
Knighter/scripts/a_rule_triage.py：规则层命令行入口，支持 triage、enrich_code_context、export_for_llm。
Knighter/scripts/cppcheck_xml_to_findings.py：将 cppcheck XML 报告转换为统一 findings JSON 格式。
Knighter/scripts/run_a_pipeline.py：一键流水线脚本，串联 cppcheck 扫描、规则预处理与 JSONL 导出。
Knighter/scripts/a_ruleset.cppcheck_focus.json：默认降噪规则集，过滤 style、unused 等噪声告警。
Knighter/scripts/a_ruleset.example.json：规则集配置示例，可按项目自定义过滤条件。
Knighter/scripts/a_ruleset.kernel_supplement.json：补充实验用规则集，过滤 missingIncludeSystem 等内核单文件扫描噪声。
Knighter/scripts/make_sample_target.py：生成示例 C 目标代码，用于本地复现与演示。

code/sample_target/：示例 C 目标代码目录，供 cppcheck 扫描与 code_context 补全使用。
code/linux-kernel/drivers/char/mem.c：Linux 6.6 真实内核源码文件，用于补充实验（drivers/char 字符设备模块）。
artifacts/linux-6.6-mem/：补充实验产物（mem.c 扫描后的 findings、triage 报告与 JSONL）。
for_llm.cppcheck.with_ctx.v2.jsonl：供 LLM 判定阶段使用的 JSONL 输入，含 code_context。
triage_cppcheck.with_ctx.v2.json：规则层 triage 分析报告，含 summary、analysis 统计与典型样例。

final_report.json：最终实验报告，融合两轮判定结果，对每个缺陷给出最终 verdict（true / false / uncertain），并包含完整的流水线统计
