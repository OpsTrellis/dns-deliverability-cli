#!/usr/bin/env node

/**
 * OpsTrellis DNS Deliverability CLI
 * Copyright (c) 2026 OpsTrellis (https://opstrellis.com)
 */

import { auditDomain } from '../src/index.js';

const targetDomain = process.argv[2];

if (!targetDomain || targetDomain === '--help' || targetDomain === '-h') {
  console.log(`
OpsTrellis DNS Deliverability Auditor
Audit your domain's SPF, DKIM, DMARC, and MX setup in seconds.

USAGE:
  npx @opstrellis/dns-deliverability-cli <domain>
  node bin/cli.js <domain>

EXAMPLES:
  node bin/cli.js opstrellis.com
  node bin/cli.js google.com

WEB AUDIT SUITE:
  Full web audit & fix generators: https://opstrellis.com/tools/domain-health/
`);
  process.exit(targetDomain ? 0 : 1);
}

async function run() {
  console.log(`\n=====================================================`);
  console.log(`  OpsTrellis Deliverability Auditor  (v1.0.0)`);
  console.log(`  Auditing: ${targetDomain}`);
  console.log(`=====================================================\n`);

  try {
    const res = await auditDomain(targetDomain);

    const formatBadge = (status) => {
      if (status === 'PASS') return '[ PASS ]';
      if (status === 'WARN') return '[ WARN ]';
      return '[ FAIL ]';
    };

    console.log(`1. MX Records: ${formatBadge(res.mx.status)}`);
    if (res.mx.found) {
      res.mx.records.forEach(r => console.log(`   - Priority ${r.priority}: ${r.exchange}`));
    } else {
      console.log(`   No MX records found. Domain cannot receive emails.`);
    }

    console.log(`\n2. SPF Record: ${formatBadge(res.spf.status)}`);
    if (res.spf.found) {
      console.log(`   ${res.spf.record}`);
    } else {
      console.log(`   Missing SPF record. Inboxes may flag your outbound mail as spam.`);
    }

    console.log(`\n3. DMARC Policy: ${formatBadge(res.dmarc.status)}`);
    if (res.dmarc.found) {
      console.log(`   Policy: ${res.dmarc.policy}`);
      console.log(`   Raw: ${res.dmarc.record}`);
    } else {
      console.log(`   Missing DMARC record. Required by Gmail & Yahoo for bulk sending.`);
    }

    console.log(`\n4. DKIM Signatures:`);
    if (res.dkim.foundSelectors.length > 0) {
      res.dkim.foundSelectors.forEach(s => {
        console.log(`   ✔ Found selector [${s.selector}]: ${s.record.substring(0, 60)}...`);
      });
    } else {
      console.log(`   ℹ Probed common selectors (${res.dkim.testedSelectors.join(', ')}). No default selector found. Ensure your custom selector is configured.`);
    }

    console.log(`\n-----------------------------------------------------`);
    console.log(`Overall Health Score: ${res.summary.score} / 100 [${res.summary.status}]`);
    console.log(`-----------------------------------------------------`);
    console.log(`Need full SPF/DKIM/DMARC repair or cold outbound infrastructure?`);
    console.log(`Visit https://opstrellis.com or run the web audit at https://opstrellis.com/tools/domain-health/\n`);

  } catch (err) {
    console.error(`Audit failed: ${err.message}`);
    process.exit(1);
  }
}

run();
