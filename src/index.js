import dns from 'node:dns/promises';

/**
 * OpsTrellis DNS & Deliverability Auditor
 * Audits SPF, DKIM, DMARC, and MX records for any given domain.
 * https://opstrellis.com
 */

export async function auditDomain(domain) {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const report = {
    domain: cleanDomain,
    timestamp: new Date().toISOString(),
    mx: { found: false, records: [], status: 'FAIL' },
    spf: { found: false, record: null, status: 'FAIL', issues: [] },
    dmarc: { found: false, record: null, policy: null, status: 'FAIL', issues: [] },
    dkim: { testedSelectors: [], foundSelectors: [] },
    summary: { score: 0, status: 'POOR' }
  };

  let points = 0;

  // 1. Audit MX Records
  try {
    const mxRecords = await dns.resolveMx(cleanDomain);
    if (mxRecords && mxRecords.length > 0) {
      report.mx.found = true;
      report.mx.records = mxRecords.sort((a, b) => a.priority - b.priority);
      report.mx.status = 'PASS';
      points += 25;
    }
  } catch (err) {
    report.mx.issues = [err.code === 'ENODATA' ? 'No MX records found' : err.message];
  }

  // 2. Audit SPF Record
  try {
    const txtRecords = await dns.resolveTxt(cleanDomain);
    const flatTxt = txtRecords.map(r => r.join(''));
    const spfRecord = flatTxt.find(r => r.startsWith('v=spf1'));

    if (spfRecord) {
      report.spf.found = true;
      report.spf.record = spfRecord;
      if (spfRecord.includes('-all')) {
        report.spf.status = 'PASS';
        points += 25;
      } else if (spfRecord.includes('~all')) {
        report.spf.status = 'WARN';
        report.spf.issues.push('Softfail (~all) detected. Consider hardfail (-all) for strict enforcement.');
        points += 20;
      } else {
        report.spf.status = 'WARN';
        report.spf.issues.push('Permissive SPF policy detected (missing -all or ~all).');
        points += 10;
      }
    } else {
      report.spf.issues.push('No v=spf1 TXT record found on root domain.');
    }
  } catch (err) {
    report.spf.issues.push(err.code === 'ENODATA' ? 'No TXT records found' : err.message);
  }

  // 3. Audit DMARC Record
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
    const flatDmarc = dmarcRecords.map(r => r.join(''));
    const dmarcRecord = flatDmarc.find(r => r.startsWith('v=DMARC1'));

    if (dmarcRecord) {
      report.dmarc.found = true;
      report.dmarc.record = dmarcRecord;

      const pMatch = dmarcRecord.match(/p=([a-zA-Z]+)/);
      report.dmarc.policy = pMatch ? pMatch[1].toLowerCase() : 'unknown';

      if (report.dmarc.policy === 'reject') {
        report.dmarc.status = 'PASS';
        points += 25;
      } else if (report.dmarc.policy === 'quarantine') {
        report.dmarc.status = 'PASS';
        points += 22;
      } else if (report.dmarc.policy === 'none') {
        report.dmarc.status = 'WARN';
        report.dmarc.issues.push('DMARC policy is set to "p=none" (monitoring only; does not protect from spoofing).');
        points += 15;
      }
    } else {
      report.dmarc.issues.push('No v=DMARC1 record found at _dmarc.' + cleanDomain);
    }
  } catch (err) {
    report.dmarc.issues.push(err.code === 'ENODATA' ? 'Missing _dmarc TXT record' : err.message);
  }

  // 4. Probe Common DKIM Selectors
  const commonSelectors = ['google', 'k1', 's1', 'default', 'mail', 'selector1', 'sig1'];
  report.dkim.testedSelectors = commonSelectors;

  for (const selector of commonSelectors) {
    try {
      const dkimTxt = await dns.resolveTxt(`${selector}._domainkey.${cleanDomain}`);
      const joined = dkimTxt.map(r => r.join(''));
      const dkimRec = joined.find(r => r.includes('v=DKIM1') || r.includes('p='));
      if (dkimRec) {
        report.dkim.foundSelectors.push({ selector, record: dkimRec });
      }
    } catch {
      // Selector not found, ignore
    }
  }

  if (report.dkim.foundSelectors.length > 0) {
    points += 25;
  }

  report.summary.score = points;
  if (points >= 90) report.summary.status = 'EXCELLENT';
  else if (points >= 70) report.summary.status = 'GOOD';
  else if (points >= 40) report.summary.status = 'FAIR';
  else report.summary.status = 'CRITICAL';

  return report;
}
