import json
import re
import time
import requests
import argparse

#配置
DEFAULT_CONFIG = {
    "api_url": "https://api.deepseek.com/v1",
    "model_name": "deepseek-chat",
    "api_key": "sk-2e1536edf32d48b180d573e77ce0cb58",
    "temperature": 0.3,
    "temperature_round2": 0.5,
    "max_tokens": 512,
    "timeout": 60
}

USE_MOCK = True

# 默认值，会被命令行参数覆盖
INPUT_FILE = "for_llm.jsonl"
OUTPUT_FILE = "llm_judgments.json"

def extract_code_from_context(code_context):
    if not code_context:
        return ""
    lines = code_context.strip().split('\n')
    if len(lines) <= 1:
        return code_context
    code_lines = []
    for line in lines[1:]:
        match = re.match(r'^\s*(?:>>)?\s*\d+\s*\|\s*(.*)$', line)
        if match:
            code = match.group(1).rstrip()
            if code and not code.isspace():
                code_lines.append(code)
    return '\n'.join(code_lines) if code_lines else code_context

class LLMClient:
    def __init__(self, config, use_mock=True):
        self.config = config
        self.use_mock = use_mock

    def chat(self, prompt, temperature=None):
        if self.use_mock:
            return self._mock_response(prompt)
        return self._real_call(prompt, temperature)

    def _real_call(self, prompt, temperature=None):
        temp = temperature if temperature is not None else self.config["temperature"]
        headers = {
            "Authorization": f"Bearer {self.config['api_key']}",
            "Content-Type": "application/json"
        }
        messages = [
            {"role": "system", "content": "你是代码安全审计专家，只输出JSON格式。"},
            {"role": "user", "content": prompt}
        ]
        payload = {
            "model": self.config["model_name"],
            "messages": messages,
            "temperature": temp,
            "max_tokens": self.config["max_tokens"]
        }
        
        print(f"    调用API...")
        response = requests.post(
            f"{self.config['api_url']}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.config["timeout"]
        )
        
        print(f"    状态码: {response.status_code}")
        
        if response.status_code != 200:
            print(f"    错误信息: {response.text}")
            return '{"is_real_bug": null, "reason": "API调用失败: ' + str(response.status_code) + '", "fp_category": "unknown"}'
        
        result = response.json()
        
        if "choices" not in result:
            print(f"    返回数据: {result}")
            return '{"is_real_bug": null, "reason": "API返回格式错误", "fp_category": "unknown"}'
        
        return result["choices"][0]["message"]["content"]

    def _mock_response(self, prompt):
        mock_results = {
            "Null pointer": '{"is_real_bug": false, "reason": "解引用发生在空指针检查之前，实际运行时s不可能为NULL", "fp_category": "path"}',
            "Stack-based buffer": '{"is_real_bug": true, "reason": "strcpy无长度限制，可导致栈溢出", "fp_category": "none"}',
            "Memory leak": '{"is_real_bug": false, "reason": "ptr在函数末尾被free，仅特定分支泄露", "fp_category": "path"}',
            "Double unlock": '{"is_real_bug": true, "reason": "连续两次unlock，未定义行为", "fp_category": "none"}',
            "Use after free": '{"is_real_bug": true, "reason": "free后立即解引用", "fp_category": "none"}',
            "Integer overflow": '{"is_real_bug": false, "reason": "未确认实际风险", "fp_category": "other"}',
            "Uninitialized scalar": '{"is_real_bug": true, "reason": "未初始化变量用于条件判断", "fp_category": "none"}',
            "Division by zero": '{"is_real_bug": false, "reason": "调用方可能已保证非零", "fp_category": "path"}',
            "Hardcoded password": '{"is_real_bug": true, "reason": "硬编码密码有安全风险", "fp_category": "none"}',
            "Array index out of bounds": '{"is_real_bug": true, "reason": "未检查索引范围", "fp_category": "none"}',
            "Insecure random": '{"is_real_bug": true, "reason": "rand()非密码学安全", "fp_category": "none"}',
            "Deadlock potential": '{"is_real_bug": false, "reason": "锁顺序一致，无死锁", "fp_category": "path"}',
            "Format string": '{"is_real_bug": true, "reason": "用户输入作为格式参数", "fp_category": "none"}',
            "Obsolete function 'gets'": '{"is_real_bug": true, "reason": "gets不安全，已被弃用", "fp_category": "none"}',
            "Resource leak": '{"is_real_bug": true, "reason": "fopen未调用fclose", "fp_category": "none"}',
            "MD5": '{"is_real_bug": false, "reason": "MD5可能仅用于校验和", "fp_category": "other"}',
            "Command injection": '{"is_real_bug": true, "reason": "system执行外部命令", "fp_category": "none"}',
            "Out-of-bounds pointer": '{"is_real_bug": false, "reason": "指针算术无解引用", "fp_category": "other"}',
            "thread safety": '{"is_real_bug": false, "reason": "线程安全警告非直接缺陷", "fp_category": "other"}',
            "Double free": '{"is_real_bug": true, "reason": "连续两次free", "fp_category": "none"}',
        }
        for key, value in mock_results.items():
            if key.lower() in prompt.lower():
                return value
        return '{"is_real_bug": null, "reason": "需要人工审查", "fp_category": "unknown"}'

class DefectJudge:
    def __init__(self, llm_client):
        self.llm_client = llm_client

    def build_prompt(self, finding):
        location = finding.get("location", {})
        raw_context = finding.get("code_context", "")
        code = extract_code_from_context(raw_context)
        if not code:
            code = "// 代码上下文缺失"
        prompt = '判断以下缺陷是真实漏洞还是误报。\n\n'
        prompt += '缺陷ID: ' + str(finding.get('id', 'unknown')) + '\n'
        prompt += '位置: ' + str(location.get('file', 'unknown')) + ':' + str(location.get('line', '?')) + '\n'
        prompt += '描述: ' + str(finding.get('message', '')) + '\n'
        prompt += '严重性: ' + str(finding.get('severity', '')) + '\n\n'
        prompt += '代码:\n```c\n' + code + '\n```\n\n'
        prompt += '输出JSON格式(只输出JSON): {"is_real_bug": true/false/null, "reason": "理由", "fp_category": "none/path/other"}'
        return prompt

    def parse_response(self, response):
        try:
            response = response.strip()
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                response = response[start:end].strip()
            result = json.loads(response)
            return {
                "is_real_bug": result.get("is_real_bug"),
                "reason": result.get("reason", ""),
                "fp_category": result.get("fp_category", "unknown")
            }
        except:
            return {"is_real_bug": None, "reason": "解析失败", "fp_category": "unknown"}

    def judge_single(self, finding, round_num=1):
        prompt = self.build_prompt(finding)
        temp = 0.3 if round_num == 1 else 0.5
        response = self.llm_client.chat(prompt, temperature=temp)
        return self.parse_response(response)

    def judge_two_rounds(self, finding):
        round1 = self.judge_single(finding, round_num=1)
        time.sleep(1)
        round2 = self.judge_single(finding, round_num=2)
        agree = round1["is_real_bug"] == round2["is_real_bug"]
        uncertain = not agree or round1["is_real_bug"] is None
        if agree and round1["is_real_bug"] is not None:
            final_is_real_bug = round1["is_real_bug"]
            final_fp_category = round1["fp_category"]
            final_reason = round1["reason"]
        else:
            final_is_real_bug = None
            final_fp_category = "uncertain"
            final_reason = f"两轮不一致: R1={round1['is_real_bug']}, R2={round2['is_real_bug']}"
        return {
            "finding_id": finding.get("id"),
            "raw": finding.get("raw", ""),
            "location": finding.get("location", {}),
            "message": finding.get("message", ""),
            "llm_round1": round1,
            "llm_round2": round2,
            "llm_agree": agree,
            "uncertain": uncertain,
            "is_real_bug": final_is_real_bug,
            "fp_category": final_fp_category,
            "reason": final_reason
        }

    def process_batch(self, findings):
        results = []
        total = len(findings)
        for i, finding in enumerate(findings, 1):
            print(f"\n[{i}/{total}] 处理: {finding.get('id')}")
            results.append(self.judge_two_rounds(finding))
        return results

def parse_args():
    parser = argparse.ArgumentParser(description='LLM缺陷判定程序')
    parser.add_argument('-i', '--input', default=INPUT_FILE, help='输入文件路径(JSONL格式)')
    parser.add_argument('-o', '--output', default=OUTPUT_FILE, help='输出文件路径(JSON格式)')
    parser.add_argument('--mock', action='store_true', help='使用模拟模式(无需API)')
    parser.add_argument('--real', action='store_true', help='使用真实API模式')
    return parser.parse_args()

def main():
    global INPUT_FILE, OUTPUT_FILE, USE_MOCK
    
    args = parse_args()
    
    # 更新输入输出文件
    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    
    # 更新模式
    if args.mock:
        USE_MOCK = True
    elif args.real:
        USE_MOCK = False
    
    print(f"输入文件: {INPUT_FILE}")
    print(f"输出文件: {OUTPUT_FILE}")
    print(f"运行模式: {'模拟模式' if USE_MOCK else '真实API模式'}")
    
    findings = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(json.loads(line))
    
    print(f"共 {len(findings)} 个缺陷")
    
    llm_client = LLMClient(DEFAULT_CONFIG, use_mock=USE_MOCK)
    judge = DefectJudge(llm_client)
    results = judge.process_batch(findings)
    
    real_bugs = sum(1 for r in results if r.get("is_real_bug") is True)
    false_pos = sum(1 for r in results if r.get("is_real_bug") is False)
    uncertain = sum(1 for r in results if r.get("uncertain") is True)
    
    output = {
        "summary": {
            "total": len(results),
            "verdict_real_bug": real_bugs,
            "verdict_false_positive": false_pos,
            "uncertain": uncertain,
            "false_positive_by_category": {
                "path": sum(1 for r in results if r.get("fp_category") == "path"),
                "other": sum(1 for r in results if r.get("fp_category") == "other"),
                "uncertain": uncertain
            }
        },
        "findings": results
    }
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    
    print(f"\n完成！真实漏洞: {real_bugs}, 误报: {false_pos}, 不确定: {uncertain}")
    print(f"结果已保存到: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
