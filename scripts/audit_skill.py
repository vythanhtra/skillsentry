#!/usr/bin/env python3
"""
SkillSentry — AI Skill Security Scanner
Detects malicious behavior chains, obfuscation, and prompt injection
in AI skill files before installation.

Usage:
    python audit_skill.py path/to/SKILL.md
    python audit_skill.py --all
    python audit_skill.py SKILL.md --json
    python audit_skill.py --all --discord "https://discord.com/api/webhooks/..."
    python audit_skill.py --all --telegram "BOT_TOKEN:CHAT_ID"
"""

import re
import sys
import os
import json
import base64
import codecs
import argparse
import datetime
import urllib.request
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
#  HOMOGLYPH TABLE
# ──────────────────────────────────────────────
HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
    'с': 'c', 'у': 'y', 'х': 'x',
    'Ⅰ': 'I',
    '０': '0', '１': '1', 'ａ': 'a', 'ｂ': 'b',
    'ℯ': 'e', 'ℓ': 'l', 'ℴ': 'o',
    # Extended Latin lookalikes
    'Ɛᴬᵹꜱꜱ': 'a',
}

ZERO_WIDTH_CHARS = {
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\uFEFF',  # BOM
    '\u2060',  # Word Joiner
    '\u202E',  # Right-to-Left Override ← CRITICAL
    '\u2028',  # Line Separator
    '\u2029',  # Paragraph Separator
}

# ──────────────────────────────────────────────
#  BEHAVIOR CHAIN ACTION PATTERNS
# ──────────────────────────────────────────────
ACTION_PATTERNS = {
    'READ_SENSITIVE': re.compile(
        r'(?i)(\.env\b|\.aws[/\\]|\.ssh[/\\]|api[_-]?key|password|token|'
        r'secret|credential|private[_-]?key|database[_-]?url|db[_-]?url|'
        r'GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)'
    ),
    'NETWORK_SEND': re.compile(
        r'(?i)(curl\b|wget\b|Invoke-WebRequest|requests\.(get|post|put|patch)|'
        r'fetch\(|urllib|http\.client|aiohttp|httpx|\.post\(|\.get\(http|'
        r'socket\.connect|smtplib|ftplib)'
    ),
    'FILE_DELETE': re.compile(
        r'(?i)(rm\s+-[rf]|del\s+[/\\]|Remove-Item|os\.remove\(|os\.unlink\(|'
        r'shutil\.rmtree|Path.*\.unlink\(\)|glob.*rm)'
    ),
    'EXEC_DYNAMIC': re.compile(
        r'(?i)(eval\(|exec\(|os\.system\(|subprocess\.|__import__\(|'
        r'compile\s*\(|execfile\(|ctypes\.|cffi\.)'
    ),
    'WRITE_SYSTEM': re.compile(
        r'(?i)(~[/\\]\.ssh|~[/\\]\.aws|~[/\\]\.bashrc|~[/\\]\.zshrc|'
        r'/etc/passwd|/etc/crontab|/etc/hosts|HKEY_|winreg\.|'
        r'\.git[/\\]hooks[/\\]|\.git[/\\]config)'
    ),
    'BASE64_EXEC': re.compile(
        r'(?i)(base64\s*[-\.]\s*d|b64decode|frombase64|atob\(|'
        r'echo\s+.*\|\s*base64\s*-d\s*\|\s*(bash|sh|python|node)|'
        r'powershell.*-enc)'
    ),
    # NEW: Cloud metadata SSRF
    'SSRF_METADATA': re.compile(
        r'(?i)(169\.254\.169\.254|metadata\.google\.internal|'
        r'169\.254\.170\.2|fd00:ec2::254|'
        r'instance-data\.ec2\.internal)'
    ),
    # NEW: Git hook injection
    'GIT_HOOK': re.compile(
        r'(?i)(\.git[/\\]hooks[/\\]|git\s+hooks\s+install|'
        r'husky\s+install|pre-commit\s+install|'
        r'echo\s+.*>\s*\.git[/\\]hooks[/\\])'
    ),
    # NEW: Clipboard access
    'CLIPBOARD': re.compile(
        r'(?i)(pbpaste|pbcopy|Get-Clipboard|Set-Clipboard|'
        r'xclip|xdotool|pyperclip|clipboard\.get|'
        r'ctypes.*CF_TEXT)'
    ),
    # NEW: Package file modification
    'PACKAGE_MOD': re.compile(
        r'(?i)(requirements\.txt|package\.json|Pipfile|pyproject\.toml|'
        r'Cargo\.toml|go\.sum)\s*[^a-z]*(write|append|modify|add|install)'
    ),
}

DANGEROUS_CHAINS = [
    {
        'name': 'Data Exfiltration',
        'requires': ['READ_SENSITIVE', 'NETWORK_SEND'],
        'severity': 'CRITICAL', 'weight': 90,
        'description': 'Reads sensitive data and sends over network',
    },
    {
        'name': 'Upload & Cover Tracks',
        'requires': ['NETWORK_SEND', 'FILE_DELETE'],
        'severity': 'CRITICAL', 'weight': 85,
        'description': 'Uploads data then deletes evidence',
    },
    {
        'name': 'Read & Destroy',
        'requires': ['READ_SENSITIVE', 'FILE_DELETE'],
        'severity': 'CRITICAL', 'weight': 80,
        'description': 'Reads credentials then self-destructs',
    },
    {
        'name': 'Obfuscated Execution',
        'requires': ['BASE64_EXEC', 'EXEC_DYNAMIC'],
        'severity': 'CRITICAL', 'weight': 85,
        'description': 'Decodes and executes hidden payload',
    },
    {
        'name': 'System Persistence',
        'requires': ['WRITE_SYSTEM', 'EXEC_DYNAMIC'],
        'severity': 'HIGH', 'weight': 70,
        'description': 'Installs backdoor or startup hook',
    },
    {
        'name': 'Full Exfil Chain',
        'requires': ['READ_SENSITIVE', 'NETWORK_SEND', 'FILE_DELETE'],
        'severity': 'CRITICAL', 'weight': 100,
        'description': 'Complete read → upload → destroy sequence',
    },
    # NEW chains
    {
        'name': 'Cloud Credential Theft',
        'requires': ['SSRF_METADATA', 'NETWORK_SEND'],
        'severity': 'CRITICAL', 'weight': 95,
        'description': 'Cloud metadata SSRF to steal IAM credentials',
    },
    {
        'name': 'Git Hook Backdoor',
        'requires': ['GIT_HOOK', 'EXEC_DYNAMIC'],
        'severity': 'CRITICAL', 'weight': 88,
        'description': 'Injects malicious git hooks for persistence',
    },
    {
        'name': 'Git Hook Exfil',
        'requires': ['GIT_HOOK', 'NETWORK_SEND'],
        'severity': 'HIGH', 'weight': 75,
        'description': 'Git hook triggers silent data upload',
    },
    {
        'name': 'Clipboard Harvest',
        'requires': ['CLIPBOARD', 'NETWORK_SEND'],
        'severity': 'HIGH', 'weight': 72,
        'description': 'Reads clipboard (passwords/tokens) and exfiltrates',
    },
]

# ──────────────────────────────────────────────
#  PROMPT INJECTION PATTERNS
# ──────────────────────────────────────────────
INJECTION_PATTERNS = [
    {
        'id': 'instruction_override',
        'pattern': re.compile(
            r'(?i)(?:ignore|disregard|forget|override|bypass)\s+'
            r'(?:all\s+)?(?:your\s+|the\s+)?'
            r'(?:previous|prior|above|original|system)\s+'
            r'(?:instructions?|prompts?|rules?|guidelines?|constraints?)'
        ),
        'severity': 'CRITICAL', 'weight': 40,
        'description': 'Attempts to override system instructions',
    },
    {
        'id': 'delimiter_injection',
        'pattern': re.compile(
            r'(?i)(?:\[/?SYSTEM\]|\[/?INST\]|'
            r'<\|(?:im_start|im_end|system|user|assistant)\|>|'
            r'<<SYS>>|<\/s>|\[/?SYS\])'
        ),
        'severity': 'CRITICAL', 'weight': 45,
        'description': 'Injects role delimiters to hijack conversation',
    },
    {
        'id': 'jailbreak_dan',
        'pattern': re.compile(
            r'(?i)\b(?:DAN|do\s+anything\s+now|developer\s+mode|'
            r'god\s+mode|sudo\s+mode|jailbreak(?:ed)?|'
            r'unrestricted\s+mode|no\s+restrictions)\b'
        ),
        'severity': 'HIGH', 'weight': 35,
        'description': 'DAN-style jailbreak attempt',
    },
    {
        'id': 'jailbreak_roleplay',
        'pattern': re.compile(
            r'(?i)(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|'
            r'roleplay\s+as|from\s+now\s+on\s+you\s+are)\s+'
            r'(?:(?:a|an)\s+)?(?:different|new|unrestricted|evil|malicious)'
        ),
        'severity': 'CRITICAL', 'weight': 40,
        'description': 'Roleplay jailbreak to bypass constraints',
    },
    {
        'id': 'encoded_payload',
        'pattern': re.compile(
            r'(?i)(?:decode|base64|eval|execute)\s*(?:\(|:)\s*'
            r'[A-Za-z0-9+/]{20,}={0,2}'
        ),
        'severity': 'HIGH', 'weight': 30,
        'description': 'Encoded payload to evade text filters',
    },
    {
        'id': 'html_comment_injection',
        'pattern': re.compile(
            r'(?i)<!--\s*(?:system|instruction|override|ignore|forget)'
            r'[\s\S]*?-->'
        ),
        'severity': 'HIGH', 'weight': 35,
        'description': 'Hidden instructions in HTML comments',
    },
    {
        'id': 'token_smuggling',
        'pattern': re.compile(
            r'(?i)(?:ignore\s+(?:the\s+)?(?:following|next|rest)|'
            r'skip\s+to\s+(?:the\s+)?end|'
            r'begin\s+(?:new|real)\s+(?:task|instruction))'
        ),
        'severity': 'MEDIUM', 'weight': 25,
        'description': 'Smuggles tokens to redirect AI behavior',
    },
    {
        'id': 'prompt_leak_indirect',
        'pattern': re.compile(
            r'(?i)(?:translate|summarize|rephrase|rewrite)\s+'
            r'(?:your|the|all)?\s*'
            r'(?:system|initial|original|hidden|secret)\s+'
            r'(?:prompt|instructions?|message|rules?)\s+(?:to|in|into)'
        ),
        'severity': 'HIGH', 'weight': 30,
        'description': 'Indirect system prompt extraction via translation/summary',
    },
    # NEW
    {
        'id': 'context_window_overflow',
        'pattern': re.compile(
            r'(?i)(?:repeat\s+(?:the\s+)?(?:following|this)\s+(?:\d+\s+)?times|'
            r'print\s+(?:the\s+)?(?:previous|above)\s+(?:\d+\s+)?times|'
            r'(?:copy|duplicate|echo)\s+.*\s*\*\s*(?:\d{3,}))'
        ),
        'severity': 'MEDIUM', 'weight': 20,
        'description': 'Context window flood to obscure malicious content',
    },
    {
        'id': 'prompt_injection_via_url',
        'pattern': re.compile(
            r'(?i)https?://[^\s]*(?:ignore|override|system|jailbreak|DAN)[^\s]*'
        ),
        'severity': 'HIGH', 'weight': 30,
        'description': 'Malicious instruction embedded in URL parameter',
    },
]

# ──────────────────────────────────────────────
#  URL & OBFUSCATION SCANNERS
# ──────────────────────────────────────────────
URL_SHORTENERS = re.compile(
    r'(?i)https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|'
    r'rb\.gy|short\.io|cutt\.ly|ow\.ly|tiny\.cc|lnkd\.in)/\S+'
)
IP_URL = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/?[^\s]*')
HEX_URL = re.compile(r'(?i)https?://[^\s]*(?:%[0-9a-f]{2}){3,}[^\s]*')
BASE64_BLOCK = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# NEW: ROT13 detection
ROT13_INDICATORS = re.compile(
    r'(?i)(codecs\.decode|\.encode\s*\(\s*[\'"]rot|rot-?13|'
    r"str\.maketrans.*'n-za-m'|str\.maketrans.*'N-ZA-M')"
)

# NEW: XOR obfuscation
XOR_INDICATORS = re.compile(
    r'(?i)(chr\s*\(\s*ord\s*\(.*\)\s*\^\s*\d+|'
    r'[\w]+\s*\^\s*\d+\s*for\s+[\w]+\s+in\s+b[\'"]|'
    r'bytes\(\[.*\^\s*\d+.*\]\))'
)

# NEW: Time-bomb indicators
TIME_BOMB = re.compile(
    r'(?i)(datetime\.now\(\)|datetime\.today\(\)|time\.time\(\))\s*'
    r'(?:[><=!]{1,2}|\.hour\s*==|\.day\s*==|\.month\s*==|\.weekday\(\)\s*==)'
)

# NEW: Package poisoning
PACKAGE_POISON = re.compile(
    r'(?i)(?:pip\s+install|npm\s+install|yarn\s+add|go\s+get|cargo\s+add)\s+'
    r'(?:--index-url|--extra-index-url|-i)\s+https?://(?!pypi\.org|npmjs\.com)'
)

TRUSTED_DOMAINS = [
    'github.com/anthropics',
    'docs.anthropic.com',
    'api.anthropic.com',
    'raw.githubusercontent.com/anthropics',
    'docs.claude.ai',
    'pypi.org',
    'npmjs.com',
    'nodejs.org',
    'python.org',
]


# ──────────────────────────────────────────────
#  DEOBFUSCATION ENGINE
# ──────────────────────────────────────────────
def strip_code_fences(text: str) -> str:
    """
    Returns text with code fence markers stripped but content preserved.
    Ensures malicious code inside ``` blocks is still scanned.
    """
    return re.sub(r'```[a-zA-Z]*\n?', '', text)


def normalize_unicode(text: str) -> tuple[str, list[str]]:
    """Remove zero-width chars + replace homoglyphs."""
    issues = []
    result = []
    zw_found = set()

    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            zw_found.add(f'U+{ord(ch):04X}')
            continue
        result.append(HOMOGLYPHS.get(ch, ch))

    if zw_found:
        issues.append(f"Zero-width chars: {', '.join(sorted(zw_found))}")

    cleaned = ''.join(result)
    if cleaned != text.translate({ord(k): None for k in ZERO_WIDTH_CHARS}):
        issues.append("Homoglyph substitution detected")

    return cleaned, issues


def remove_splitters(text: str) -> str:
    """Detect split keywords: 'b.y.p.a.s.s' → 'bypass'."""
    dot_split = re.sub(r'\b(\w\.)+\w\b', lambda m: m.group(0).replace('.', ''), text)
    if dot_split != text:
        return dot_split
    words = text.split()
    if len(words) > 3 and all(len(w) <= 2 for w in words):
        return ''.join(words)
    return text


def decode_base64_blocks(text: str) -> list[dict]:
    """Find, decode and flag suspicious base64 blocks."""
    results = []
    for match in BASE64_BLOCK.finditer(text):
        val = match.group(0)
        for enc in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded = enc(val + '==').decode('utf-8', errors='ignore')
                ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
                if len(decoded) >= 4 and ratio > 0.8:
                    results.append({
                        'original': val[:30] + ('...' if len(val) > 30 else ''),
                        'decoded': decoded[:200],
                        'suspicious': any(p.search(decoded) for p in ACTION_PATTERNS.values()),
                    })
                    break
            except Exception:
                pass
    return results


def detect_rot13(text: str) -> list[str]:
    """Detect ROT13 obfuscation patterns."""
    findings = []
    if ROT13_INDICATORS.search(text):
        findings.append("ROT13 encoding detected — possible instruction obfuscation")
    # Also try to decode any obvious rot13 strings in the text
    rot13_text = codecs.encode(text, 'rot_13')
    for pat in ACTION_PATTERNS.values():
        if pat.search(rot13_text):
            findings.append("ROT13-decoded content matches dangerous pattern")
            break
    return findings


def detect_xor(text: str) -> list[str]:
    """Detect XOR-based obfuscation."""
    if XOR_INDICATORS.search(text):
        return ["XOR byte-level obfuscation detected"]
    return []


def detect_time_bomb(text: str) -> list[str]:
    """Detect time-conditional execution patterns."""
    findings = []
    if TIME_BOMB.search(text):
        findings.append("Time-conditional execution — possible time-bomb payload")
    # Also look for hard-coded date checks
    if re.search(r'(?i)(if.*date.*==|if.*month.*==|if.*year.*==)\s*\d', text):
        findings.append("Hard-coded date condition — possible delayed activation")
    return findings


def detect_package_poisoning(text: str) -> list[str]:
    """Detect dependency confusion / typosquatting attacks."""
    findings = []
    if PACKAGE_POISON.search(text):
        findings.append("Custom package index URL — possible dependency confusion attack")
    # Check for known typosquatting patterns
    typosquat = re.search(
        r'(?i)(requesTs|reqests|nump y|pandaas|boto 3|anthrop1c|'
        r'anthropicc|c1aude|claude-ai-sdk)',
        text
    )
    if typosquat:
        findings.append(f"Possible typosquatted package name: {typosquat.group(0)}")
    return findings


# ──────────────────────────────────────────────
#  BEHAVIOR CHAIN ANALYZER
# ──────────────────────────────────────────────
def analyze_behavior_chains(content: str) -> tuple[dict, list]:
    """Detect action types and dangerous chains."""
    # First strip code fences so we scan code content too
    scannable = strip_code_fences(content)
    lines = scannable.split('\n')
    action_hits = {}

    for i, line in enumerate(lines, 1):
        for action, pat in ACTION_PATTERNS.items():
            if pat.search(line):
                action_hits.setdefault(action, []).append({
                    'line': i,
                    'text': line.strip()[:80],
                })

    chain_findings = []
    for chain in DANGEROUS_CHAINS:
        if all(req in action_hits for req in chain['requires']):
            chain_findings.append({
                'chain': chain['name'],
                'severity': chain['severity'],
                'weight': chain['weight'],
                'description': chain['description'],
                'actions': {req: action_hits[req][0] for req in chain['requires']},
            })

    return action_hits, chain_findings


# ──────────────────────────────────────────────
#  URL SCANNER
# ──────────────────────────────────────────────
def scan_urls(content: str) -> dict:
    all_urls = re.findall(r'https?://[^\s"\'<>\])+]+', content)
    result: dict = {
        'trusted': [], 'shorteners': [], 'ip_based': [],
        'hex_encoded': [], 'unknown': [],
    }
    for url in set(all_urls):
        if URL_SHORTENERS.match(url):
            result['shorteners'].append(url)
        elif IP_URL.match(url):
            result['ip_based'].append(url)
        elif HEX_URL.match(url):
            result['hex_encoded'].append(url)
        elif any(d in url for d in TRUSTED_DOMAINS):
            result['trusted'].append(url)
        else:
            result['unknown'].append(url)
    return result


# ──────────────────────────────────────────────
#  RISK SCORING
# ──────────────────────────────────────────────
def calculate_risk_score(
    chain_findings: list,
    evasion_issues: list,
    injection_hits: list,
    url_result: dict,
    extra_issues: list,
) -> int:
    score = 100
    for f in chain_findings:
        score -= f['weight']
    score -= len(evasion_issues) * 10
    for h in injection_hits:
        score -= h['weight']
    score -= len(url_result.get('shorteners', [])) * 15
    score -= len(url_result.get('ip_based', [])) * 20
    score -= len(url_result.get('hex_encoded', [])) * 15
    score -= len(url_result.get('unknown', [])) * 5
    score -= len(extra_issues) * 15
    return max(0, score)


def risk_level(score: int) -> str:
    if score >= 80: return '✅ SAFE'
    if score >= 60: return '⚠️  LOW RISK'
    if score >= 40: return '🟠 MEDIUM RISK'
    if score >= 20: return '🔴 HIGH RISK'
    return '🚨 CRITICAL — DO NOT INSTALL'


# ──────────────────────────────────────────────
#  WEBHOOK ALERTS
# ──────────────────────────────────────────────
def send_telegram_alert(bot_token: str, chat_id: str, message: str):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = json.dumps({
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown',
    }).encode()
    req = urllib.request.Request(
        url, data=data, headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"⚠️  Telegram alert failed: {e}")


def send_discord_alert(webhook_url: str, skill_name: str, findings: list, score: int):
    is_critical = any(f['severity'] == 'CRITICAL' for f in findings)
    color = 15158332 if is_critical else 15844367  # red / yellow
    fields = [{
        'name': f['chain'],
        'value': f['description'],
        'inline': False,
    } for f in findings[:5]]
    payload = json.dumps({
        'embeds': [{
            'title': f'[SkillSentry] 🚨 {skill_name}',
            'color': color,
            'description': f'Risk Score: **{score}/100** — {risk_level(score)}',
            'fields': fields,
            'footer': {'text': f'SkillSentry • {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'},
        }]
    }).encode()
    req = urllib.request.Request(
        webhook_url, data=payload, headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"⚠️  Discord alert failed: {e}")


# ──────────────────────────────────────────────
#  MAIN AUDIT FUNCTION
# ──────────────────────────────────────────────
def audit_file(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {'error': f'File not found: {filepath}'}

    raw_content = path.read_text(encoding='utf-8', errors='ignore')
    skill_name = path.parent.name or path.name

    # 1. Normalize unicode + evasion
    normalized, evasion_issues = normalize_unicode(raw_content)
    splitter_check = remove_splitters(normalized)
    if splitter_check != normalized:
        evasion_issues.append('Split-keyword evasion detected')

    # 2. Base64
    b64_results = decode_base64_blocks(raw_content)
    suspicious_b64 = [r for r in b64_results if r['suspicious']]
    if suspicious_b64:
        evasion_issues.append(f'{len(suspicious_b64)} suspicious Base64 block(s) decoded')

    # 3. Behavior chains (scan normalized + code-fence-stripped)
    action_hits, chain_findings = analyze_behavior_chains(normalized)

    # 4. Prompt injection
    injection_hits = []
    for pat in INJECTION_PATTERNS:
        if pat['pattern'].search(raw_content):
            injection_hits.append(pat)

    # 5. URL scan
    url_result = scan_urls(raw_content)

    # 6. Advanced obfuscation checks (NEW)
    extra_issues = []
    extra_issues.extend(detect_rot13(raw_content))
    extra_issues.extend(detect_xor(raw_content))
    extra_issues.extend(detect_time_bomb(raw_content))
    extra_issues.extend(detect_package_poisoning(raw_content))

    # SSRF cloud metadata check (standalone — extremely high risk)
    if ACTION_PATTERNS['SSRF_METADATA'].search(raw_content):
        extra_issues.append('Cloud metadata endpoint reference (SSRF risk — IAM credential theft)')

    # 7. Risk score
    score = calculate_risk_score(
        chain_findings, evasion_issues, injection_hits, url_result, extra_issues
    )

    return {
        'skill': skill_name,
        'file': str(filepath),
        'score': score,
        'risk_level': risk_level(score),
        'chain_findings': chain_findings,
        'evasion_issues': evasion_issues,
        'suspicious_b64': suspicious_b64,
        'injection_hits': [
            {'id': h['id'], 'severity': h['severity'], 'description': h['description']}
            for h in injection_hits
        ],
        'extra_issues': extra_issues,
        'urls': url_result,
        'action_hits': {k: v[:2] for k, v in action_hits.items()},
        'timestamp': datetime.datetime.now().isoformat(),
    }


# ──────────────────────────────────────────────
#  CONSOLE REPORT
# ──────────────────────────────────────────────
def print_report(report: dict):
    if 'error' in report:
        print(f"❌ {report['error']}")
        return

    w = 60
    print(f"\n{'=' * w}")
    print(f"🔍 SKILL AUDIT: {report['skill']}")
    print(f"{'=' * w}")
    print(f"Risk Level : {report['risk_level']}")
    print(f"Score      : {report['score']}/100")
    print(f"Scanned    : {report['timestamp']}")

    if report['chain_findings']:
        print(f"\n{'─' * w}")
        print("🔗 BEHAVIOR CHAINS:")
        for f in report['chain_findings']:
            print(f"  [{f['severity']}] {f['chain']} (weight: {f['weight']})")
            print(f"           {f['description']}")
            for action, hit in f['actions'].items():
                print(f"           • {action} @ line {hit['line']}: {hit['text'][:55]}")

    if report['evasion_issues']:
        print(f"\n{'─' * w}")
        print("🎭 EVASION TECHNIQUES:")
        for issue in report['evasion_issues']:
            print(f"  ⚠️  {issue}")

    if report['extra_issues']:
        print(f"\n{'─' * w}")
        print("🔬 ADVANCED THREATS:")
        for issue in report['extra_issues']:
            print(f"  🔴 {issue}")

    if report['suspicious_b64']:
        print(f"\n{'─' * w}")
        print("🔓 SUSPICIOUS BASE64:")
        for b in report['suspicious_b64'][:3]:
            print(f"  • {b['original']} → {b['decoded'][:80]}")

    if report['injection_hits']:
        print(f"\n{'─' * w}")
        print("💉 PROMPT INJECTION:")
        for h in report['injection_hits']:
            print(f"  [{h['severity']}] {h['id']}: {h['description']}")

    suspicious_urls = (
        [(u, 'shortener') for u in report['urls'].get('shorteners', [])] +
        [(u, 'IP-based') for u in report['urls'].get('ip_based', [])] +
        [(u, 'hex-encoded') for u in report['urls'].get('hex_encoded', [])]
    )
    if suspicious_urls:
        print(f"\n{'─' * w}")
        print("🌐 SUSPICIOUS URLs:")
        for url, reason in suspicious_urls:
            print(f"  ⚠️  [{reason}] {url}")

    if report['urls'].get('unknown'):
        print(f"\n  Unknown domains: {', '.join(report['urls']['unknown'][:5])}")

    print(f"\n{'─' * w}")
    verdict = "✅ SAFE TO INSTALL" if report['score'] >= 60 else "🚫 DO NOT INSTALL"
    print(f"VERDICT: {verdict}\n")


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='SkillSentry — AI Skill Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  audit_skill.py SKILL.md
  audit_skill.py --all
  audit_skill.py SKILL.md --json > report.json
  audit_skill.py --all --discord "https://discord.com/api/webhooks/..."
  audit_skill.py --all --telegram "BOT_TOKEN:CHAT_ID"
        """
    )
    parser.add_argument('files', nargs='*', help='Files or directories to audit')
    parser.add_argument('--all', action='store_true',
                        help='Scan ~/.agent/skills/ and ~/.gemini/antigravity/scratch/.agent/skills/')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')
    parser.add_argument('--telegram', metavar='TOKEN:CHAT_ID',
                        help='Send alert to Telegram on CRITICAL findings')
    parser.add_argument('--discord', metavar='WEBHOOK_URL',
                        help='Send alert to Discord on CRITICAL findings')
    args = parser.parse_args()

    targets = []
    if args.all:
        skill_dirs = [
            Path.home() / '.gemini/antigravity/scratch/.agent/skills',
            Path.home() / '.gemini/antigravity/skills',
            Path('.agent/skills'),
        ]
        for d in skill_dirs:
            if d.exists():
                targets.extend(d.glob('*/SKILL.md'))
    else:
        for f in args.files:
            p = Path(f)
            if p.is_dir():
                targets.extend(p.glob('**/*.md'))
                targets.extend(p.glob('**/*.py'))
                targets.extend(p.glob('**/*.sh'))
            elif p.exists():
                targets.append(p)

    if not targets:
        parser.print_help()
        sys.exit(1)

    all_reports, critical_found = [], []

    for target in targets:
        report = audit_file(str(target))
        all_reports.append(report)
        if report.get('score', 100) < 40:
            critical_found.append(report)
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print_report(report)

    if critical_found and (args.telegram or args.discord):
        for r in critical_found:
            if args.telegram:
                token, chat_id = args.telegram.split(':', 1)
                msg = (
                    f"🚨 *DANGEROUS SKILL DETECTED*\n\n"
                    f"`{r['skill']}`\nScore: {r['score']}/100\n"
                    f"Level: {r['risk_level']}\n"
                    f"Chains: {len(r['chain_findings'])}"
                )
                send_telegram_alert(token, chat_id, msg)
            if args.discord:
                send_discord_alert(args.discord, r['skill'], r['chain_findings'], r['score'])

    if len(all_reports) > 1:
        print(f"\n{'=' * 60}")
        print(f"SUMMARY — {len(all_reports)} files scanned")
        print(f"  Critical (< 40) : {sum(1 for r in all_reports if r.get('score', 100) < 40)}")
        print(f"  High risk (40-59): {sum(1 for r in all_reports if 40 <= r.get('score', 100) < 60)}")
        print(f"  Safe (≥ 60)     : {sum(1 for r in all_reports if r.get('score', 100) >= 60)}")
        print(f"{'=' * 60}\n")


if __name__ == '__main__':
    main()
