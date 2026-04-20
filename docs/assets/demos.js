// ============ terminal demo engine ============
const demos = {
  'demo-1': [
    { t: '<span class="term-prompt">soc@singapore</span>:<span class="term-user">~</span>$ claude triage <span class="term-key">--alert</span> mde_powershell.json', d: 0 },
    { t: '<span class="term-comment"># Parsing Microsoft Defender alert...</span>', d: 500 },
    { t: '<span class="term-ok">✓</span> Normalized 1 alert from <span class="term-key">MDE</span>', d: 800 },
    { t: '<span class="term-ok">✓</span> Extracted entities: <span class="term-str">user=jdoe, host=WKS-FIN-042</span>', d: 1100 },
    { t: '<span class="term-ok">✓</span> Process chain: <span class="term-str">winword.exe → powershell.exe -enc [b64]</span>', d: 1400 },
    { t: '', d: 1700 },
    { t: '<span class="term-header">═══ TRIAGE VERDICT ═══</span>', d: 1900 },
    { t: 'MITRE:    <span class="term-key">T1059.001</span> <span class="term-str">PowerShell</span> + <span class="term-key">T1566</span> <span class="term-str">Phishing</span>', d: 2200 },
    { t: 'Severity: <span class="term-warn">Medium</span> → <span class="term-err">HIGH</span> <span class="term-comment"># finance user + encoded cmd</span>', d: 2500 },
    { t: 'Verdict:  <span class="term-err">LIKELY TRUE POSITIVE</span>', d: 2900 },
    { t: '', d: 3100 },
    { t: '<span class="term-header">→ Recommended actions:</span>', d: 3300 },
    { t: '  1. Isolate <span class="term-str">WKS-FIN-042</span> via Defender Live Response', d: 3500 },
    { t: '  2. Decode payload, scope spearphishing campaign', d: 3700 },
    { t: '  3. Search Splunk for related IOCs (query below)', d: 3900 },
    { t: '<span class="term-ok">✓ SOAR payload ready for XSOAR playbook</span>', d: 4200 },
  ],
  'demo-2': [
    { t: '<span class="term-prompt">det-eng</span>:<span class="term-user">~</span>$ claude convert <span class="term-key">--from</span> sigma <span class="term-key">--to</span> kql', d: 0 },
    { t: '<span class="term-comment"># Loading proc_creation_susp_rundll32.yml...</span>', d: 500 },
    { t: '<span class="term-ok">✓</span> Sigma rule validated', d: 900 },
    { t: '<span class="term-ok">✓</span> Logsource: <span class="term-str">windows / process_creation</span>', d: 1200 },
    { t: '<span class="term-ok">✓</span> Target table: <span class="term-str">DeviceProcessEvents</span> (MDE)', d: 1500 },
    { t: '<span class="term-ok">✓</span> MITRE tags preserved: <span class="term-key">T1218.011</span>', d: 1800 },
    { t: '', d: 2000 },
    { t: '<span class="term-header">// Output: KQL</span>', d: 2200 },
    { t: '<span class="term-str">DeviceProcessEvents</span>', d: 2400 },
    { t: '| where <span class="term-key">FileName</span> =~ <span class="term-str">"rundll32.exe"</span>', d: 2600 },
    { t: '| where <span class="term-key">ProcessCommandLine</span> <span class="term-warn">has_any</span> (', d: 2800 },
    { t: '    <span class="term-str">"javascript:"</span>, <span class="term-str">"mshtml,RunHTMLApp"</span>,', d: 3000 },
    { t: '    <span class="term-str">"SetWindowFindStr"</span>, <span class="term-str">"-sta"</span>', d: 3200 },
    { t: ')', d: 3400 },
    { t: '| where <span class="term-key">InitiatingProcessFileName</span> !~ <span class="term-str">"explorer.exe"</span>', d: 3600 },
    { t: '', d: 3800 },
    { t: '<span class="term-warn">⚠ Tuning note:</span> rundll32 via scheduled task may cause FPs', d: 4000 },
    { t: '<span class="term-ok">✓ Ready to deploy in Sentinel / MDE</span>', d: 4300 },
  ],
  'demo-3': [
    { t: '<span class="term-prompt">ai-sec</span>:<span class="term-user">~</span>$ claude redteam <span class="term-key">--target</span> chatbot.internal', d: 0 },
    { t: '<span class="term-comment"># Generating OWASP LLM Top 10 corpus...</span>', d: 500 },
    { t: '<span class="term-ok">✓</span> 40 adversarial prompts across <span class="term-key">LLM01, LLM02, LLM06, LLM07</span>', d: 900 },
    { t: '<span class="term-ok">✓</span> Rate-limited execution @ 1 req/s', d: 1200 },
    { t: '', d: 1500 },
    { t: '  [<span class="term-ok">OK</span>] LLM01 direct_override       → <span class="term-ok">BLOCKED</span>', d: 1700 },
    { t: '  [<span class="term-ok">OK</span>] LLM01 role_confusion        → <span class="term-ok">BLOCKED</span>', d: 1900 },
    { t: '  [<span class="term-ok">OK</span>] LLM01 delimiter_confusion   → <span class="term-ok">SAFE</span>', d: 2100 },
    { t: '  [<span class="term-warn">!!</span>] LLM02 translation_echo      → <span class="term-warn">PARTIAL</span>', d: 2300 },
    { t: '  [<span class="term-err">XX</span>] LLM06 confused_deputy       → <span class="term-err">COMPROMISED</span>', d: 2500 },
    { t: '  [<span class="term-ok">OK</span>] LLM07 direct_ask            → <span class="term-ok">BLOCKED</span>', d: 2700 },
    { t: '', d: 2900 },
    { t: '<span class="term-header">═══ ASSESSMENT ═══</span>', d: 3100 },
    { t: 'Blocked:      <span class="term-ok">28 (70%)</span>', d: 3300 },
    { t: 'Safe:         <span class="term-ok">8  (20%)</span>', d: 3500 },
    { t: 'Partial:      <span class="term-warn">3  (7.5%)</span>', d: 3700 },
    { t: 'Compromised:  <span class="term-err">1  (2.5%)</span>  <span class="term-comment"># tool abuse</span>', d: 3900 },
    { t: '', d: 4100 },
    { t: '<span class="term-warn">⚠ Critical finding:</span> Excessive agency on admin_tools', d: 4300 },
    { t: '<span class="term-ok">✓ Audit report exported → assessment.md</span>', d: 4600 },
  ],
  'demo-4': [
    { t: '<span class="term-prompt">cloud-sec</span>:<span class="term-user">~</span>$ claude iam-review <span class="term-key">--policy</span> dev_role.json', d: 0 },
    { t: '<span class="term-comment"># Parsing IAM policy document...</span>', d: 500 },
    { t: '<span class="term-ok">✓</span> Version: <span class="term-str">2012-10-17</span>', d: 800 },
    { t: '<span class="term-ok">✓</span> 3 statements analyzed', d: 1100 },
    { t: '<span class="term-ok">✓</span> Cross-referencing 22 privesc patterns', d: 1400 },
    { t: '', d: 1700 },
    { t: '<span class="term-header">═══ FINDINGS (ranked by blast radius) ═══</span>', d: 1900 },
    { t: '', d: 2100 },
    { t: '<span class="term-err">[CRITICAL]</span> Score <span class="term-err">9/10</span> — PassRole chain enables privesc', d: 2300 },
    { t: '  Action:   <span class="term-key">iam:PassRole + ec2:RunInstances</span>', d: 2500 },
    { t: '  Resource: <span class="term-err">"*"</span> <span class="term-comment"># can pass ANY role to EC2</span>', d: 2700 },
    { t: '  Fix:      Scope <span class="term-key">iam:PassRole</span> + add <span class="term-key">iam:PassedToService</span>', d: 2900 },
    { t: '', d: 3100 },
    { t: '<span class="term-warn">[HIGH]</span>     Score <span class="term-warn">7/10</span> — NotAction + Allow misuse', d: 3300 },
    { t: '  Pattern:  <span class="term-str">NotAction: s3:DeleteBucket</span> <span class="term-comment"># grants ALL except one</span>', d: 3500 },
    { t: '', d: 3700 },
    { t: '<span class="term-warn">[MEDIUM]</span>   Score <span class="term-warn">5/10</span> — Missing MFA on sts:AssumeRole', d: 3900 },
    { t: '', d: 4100 },
    { t: '<span class="term-ok">✓ 3 findings · 2 remediation diffs generated</span>', d: 4400 },
    { t: '<span class="term-ok">✓ Report ready for AWS Security Specialty interview prep</span>', d: 4700 },
  ],
  'demo-5': [
    { t: '<span class="term-prompt">cloud-ir</span>:<span class="term-user">~</span>$ claude triage <span class="term-key">--guardduty</span> finding-abc123.json', d: 0 },
    { t: '<span class="term-comment"># Parsing GuardDuty finding...</span>', d: 500 },
    { t: '<span class="term-ok">✓</span> Type: <span class="term-str">UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B</span>', d: 900 },
    { t: '<span class="term-ok">✓</span> Account: <span class="term-str">123456789012</span> · Region: <span class="term-str">ap-southeast-1</span>', d: 1200 },
    { t: '<span class="term-ok">✓</span> Actor: <span class="term-str">iam::prod-admin</span> from <span class="term-err">185.220.101.42</span> (Tor exit)', d: 1500 },
    { t: '', d: 1800 },
    { t: '<span class="term-header">═══ TRIAGE VERDICT ═══</span>', d: 2000 },
    { t: 'MITRE:    <span class="term-key">TA0001</span> Initial Access + <span class="term-key">T1078.004</span> <span class="term-str">Valid Accounts: Cloud</span>', d: 2300 },
    { t: 'GD Score: <span class="term-warn">5.0 / Medium</span> → <span class="term-err">CRITICAL</span> <span class="term-comment"># prod admin + Tor</span>', d: 2600 },
    { t: 'Verdict:  <span class="term-err">TRUE POSITIVE — Confirmed malicious</span>', d: 3000 },
    { t: '', d: 3200 },
    { t: '<span class="term-header">→ Immediate actions:</span>', d: 3400 },
    { t: '  1. <span class="term-key">aws iam delete-access-key</span> <span class="term-key">--user-name</span> prod-admin', d: 3600 },
    { t: '  2. <span class="term-key">aws iam deactivate-mfa-device</span> + force rotation', d: 3800 },
    { t: '  3. Pull CloudTrail for AccessKeyId in last 24h', d: 4000 },
    { t: '  4. Notify principal owner + IR on-call', d: 4200 },
    { t: '', d: 4400 },
    { t: '<span class="term-ok">✓ SOAR payload → EventBridge → SecOps Slack</span>', d: 4600 },
    { t: '<span class="term-ok">✓ CloudTrail hunt query exported</span>', d: 4900 },
  ],
};

function playDemo(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = '';
  const lines = demos[id];
  if (!lines) return;
  const timeouts = [];

  lines.forEach((line, i) => {
    const t = setTimeout(() => {
      const div = document.createElement('div');
      div.className = 'term-line';
      div.innerHTML = line.t || '&nbsp;';
      if (i === lines.length - 1) div.classList.add('caret');
      el.appendChild(div);
      el.scrollTop = el.scrollHeight;
    }, line.d);
    timeouts.push(t);
  });

  el._timeouts = timeouts;
}

function clearDemo(id) {
  const el = document.getElementById(id);
  if (el && el._timeouts) {
    el._timeouts.forEach(t => clearTimeout(t));
  }
}

// Play demos when they enter viewport
const demoObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    const id = e.target.id;
    if (e.isIntersecting && !e.target.dataset.played) {
      e.target.dataset.played = '1';
      playDemo(id);
    }
  });
}, { threshold: 0.3 });

Object.keys(demos).forEach(id => {
  const el = document.getElementById(id);
  if (el) demoObserver.observe(el);
});

// Replay buttons
document.querySelectorAll('.replay-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.target;
    clearDemo(target);
    const el = document.getElementById(target);
    if (el) el.dataset.played = '';
    playDemo(target);
  });
});
