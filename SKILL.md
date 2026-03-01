---
name: SkillSentry
description: Kiểm tra bảo mật cho tất cả AI skills/plugins trước khi sử dụng. Phát hiện lệnh ẩn, exfiltration, mã hoá Base64, ký tự Unicode nguy hiểm, và behavior chain độc hại. Dùng khi cài skill mới, muốn audit toàn bộ skill library, hoặc kiểm tra file .md nghi ngờ.
triggers:
  - "audit skill"
  - "kiểm tra skill"
  - "skillsentry"
  - "/skillsentry"
  - "scan skill"
  - "skill có an toàn không"
  - "check for malicious"
  - "audit plugin"
  - "review skill trước khi cài"
  - "skill nghi ngờ"
source: internal
version: 2.1.0
---

# SkillSentry

Scans AI skill files for malicious patterns before you install them.

## When to Use

Run SkillSentry **before installing any third-party skill**:

- A skill shared on a forum, Discord, or group chat
- A skill from a GitHub repo you don't fully trust
- A skill from a colleague whose code you haven't reviewed
- Any `.md` file that will be added to your agent's skills directory

## When NOT to Use

- Skills you wrote yourself from scratch
- Official skills from `github.com/anthropics/claude-code`
- Skills already installed and running without issues (no retroactive benefit)

## Prerequisites

- Python 3.8 or newer — no additional packages required
- Script location: `.agent/skills/skill-auditor/scripts/audit_skill.py`

---

## Usage

### Quick audit — single file

```
"Audit this skill before I install it: path/to/SKILL.md"
```

Claude will run:
```powershell
python .agent\skills\skill-auditor\scripts\audit_skill.py path\to\SKILL.md
```

### Slash command

```
/skillsentry path/to/SKILL.md
/skillsentry --all
```

### Audit your entire skills library

```
"Kiểm tra toàn bộ skills hiện tại"
```

Runs:
```powershell
python .agent\skills\skill-auditor\scripts\audit_skill.py --all
```

### With real-time alerts

```powershell
# Discord
python audit_skill.py --all --discord "https://discord.com/api/webhooks/..."

# Telegram
python audit_skill.py --all --telegram "BOT_TOKEN:CHAT_ID"
```

### Save JSON report

```powershell
python audit_skill.py SKILL.md --json > report.json
```

---

## What It Detects (9 Layers)

| Layer | What | Examples |
|-------|------|----------|
| 1 | **Behavior Chains** | read `.env` → upload → delete |
| 2 | **Unicode Evasion** | homoglyphs, zero-width, RTLO |
| 3 | **Obfuscation** | Base64, ROT13, XOR, chr() concat, split keywords |
| 4 | **Prompt Injection** | DAN, delimiter hijack, instruction override |
| 5 | **Cloud SSRF** | AWS metadata (`169.254.169.254`), GCP, Azure |
| 6 | **Persistence** | cron jobs, startup scripts, git hooks |
| 7 | **Package Poisoning** | custom pip/npm registry, typosquatting |
| 8 | **Clipboard Harvest** | `pbpaste`, `Get-Clipboard`, `pyperclip` |
| 9 | **Time Bombs** | date-conditional execution |

### Risk Score

```
100 = Fully safe
 80+ ✅ Safe
 60+ ⚠️  Low risk — review flagged items
 40+ 🟠 Medium risk — do not install without review
 20+ 🔴 High risk — very likely malicious
  0  🚨 Critical — do not install
```

---

## Custom Rules

Add rules to `resources/rules.yaml`:

```yaml
rules:
  - id: my_rule
    pattern: 'dangerous_regex_here'
    severity: critical      # critical | high | medium | low
    category: exfiltration  # any label
    description: What this detects
    weight: 50              # subtracted from score when matched
    enabled: true
```

25 built-in rules included. See `resources/rules.yaml` for full list.

---

## Trust Policy

| Source | Trust | Action |
|--------|-------|--------|
| `github.com/anthropics/*` | ✅ | Install directly |
| Your own code | ✅ | Install directly |
| Known GitHub authors | ⚠️ | Audit first |
| Forums, chats, DMs | ⚠️ | Full audit required |
| Score < 40 | 🚫 | Do not install |

---

## If a Skill Fails

1. Do not run any command from that file
2. Delete the file immediately
3. Rotate any API keys if the skill was previously installed
4. Report the file to the source (GitHub issue, forum thread)
