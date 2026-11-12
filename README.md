# OpsTrellis DNS Deliverability CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![Deliverability](https://img.shields.io/badge/Deliverability-SPF%20%7C%20DKIM%20%7C%20DMARC-orange.svg)](https://opstrellis.com)

A lightning-fast, zero-dependency Node.js CLI tool to audit your domain's **SPF, DKIM, DMARC, and MX records** in seconds directly from your terminal.

Maintained with ❤️ by [OpsTrellis](https://opstrellis.com) — IT Automation & Deliverability Engineering.

---

## 🚀 Quick Start

Run instantly with `npx` (no installation required):

```bash
npx @opstrellis/dns-deliverability-cli yourdomain.com
```

Or install globally:

```bash
npm install -g @opstrellis/dns-deliverability-cli
opstrellis-dns yourdomain.com
```

---

## 📋 What It Audits

1. **MX Records**: Validates mail server routes and priorities to confirm incoming mail routing.
2. **SPF (`v=spf1`)**: Checks for valid syntax, alignment, and strict (`-all`) vs soft (`~all`) policies.
3. **DMARC (`v=DMARC1`)**: Verifies policy enforcement (`p=none`, `p=quarantine`, or `p=reject`) aligned with 2024+ Gmail & Yahoo sender requirements.
4. **DKIM Selectors**: Probes common provider selectors (`google`, `k1`, `default`, `s1`, `mail`) to confirm cryptographic domain key publication.
5. **Score & Actionable Recommendations**: Computes an instant health score out of 100 with clear guidance on what to fix.

---

## 💻 Example Output

```text
=====================================================
  OpsTrellis Deliverability Auditor  (v1.0.0)
  Auditing: opstrellis.com
=====================================================

1. MX Records: [ PASS ]
   - Priority 10: mail.opstrellis.com

2. SPF Record: [ PASS ]
   v=spf1 include:secureserver.net -all

3. DMARC Policy: [ PASS ]
   Policy: quarantine
   Raw: v=DMARC1; p=quarantine; pct=100;

4. DKIM Signatures:
   ✔ Found selector [default]: v=DKIM1; k=rsa; p=MIGfMA0GCS...

-----------------------------------------------------
Overall Health Score: 95 / 100 [EXCELLENT]
-----------------------------------------------------
Need full SPF/DKIM/DMARC repair or cold outbound infrastructure?
Visit https://opstrellis.com or run the web audit at https://opstrellis.com/tools/domain-health/
```

---

## 🛠️ Programmatic Usage (Node.js SDK)

You can also import the auditor into your own Node.js backend or automation script:

```javascript
import { auditDomain } from '@opstrellis/dns-deliverability-cli';

const report = await auditDomain('example.com');
console.log(report.summary.score); // 95
console.log(report.spf.record);
console.log(report.dmarc.policy);
```

---

## 🌐 Online Audit Suite & Free Tools

Prefer a web interface with visual guides and SPF/DMARC record generators?
- [OpsTrellis Domain Health Checker](https://opstrellis.com/tools/domain-health/)
- [OpsTrellis IP Blacklist Lookup](https://opstrellis.com/tools/blacklist/)
- [OpsTrellis DNS Record Generator](https://opstrellis.com/tools/dns-generator/)
- [OpsTrellis Cold Outreach Spam Checker](https://opstrellis.com/tools/spam-checker/)

---

## 📄 License

MIT License. Copyright (c) 2026 OpsTrellis. Contributions are welcome!

