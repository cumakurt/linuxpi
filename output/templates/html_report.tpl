<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LinuxPi Report - {{HOSTNAME}}</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --surface2: #1a2234; --surface3: #0d1520;
    --border: #1e2d40; --text: #e2e8f0; --text-dim: #64748b; --text-muted: #334155;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --info: #06b6d4; --success: #22c55e;
    --accent: #7c3aed;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 14px; line-height: 1.6; }

  .topbar { background: linear-gradient(90deg, #0f0f1a 0%, #1a0533 50%, #0f0f1a 100%); padding: 0.5rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(124,58,237,0.3); font-size: 0.75rem; color: var(--text-dim); }
  .topbar .brand { color: var(--critical); font-weight: bold; letter-spacing: 0.2em; }
  .topbar .scan-time { color: var(--text-dim); }

  .header { background: var(--surface3); padding: 3rem 4rem; border-bottom: 1px solid var(--border); position: relative; overflow: hidden; }
  .header::before { content: ''; position: absolute; top: -50%; left: -10%; width: 120%; height: 200%; background: radial-gradient(ellipse at 50% 50%, rgba(124,58,237,0.08) 0%, transparent 70%); pointer-events: none; }
  .header h1 { font-size: 2.5rem; letter-spacing: 0.15em; color: var(--critical); text-shadow: 0 0 30px rgba(239,68,68,0.3); font-weight: 900; }
  .header h1 span { color: var(--text-dim); font-size: 1rem; display: block; letter-spacing: 0.1em; margin-top: 0.25rem; font-weight: normal; }
  .header .target-info { margin-top: 1.5rem; display: flex; gap: 2rem; flex-wrap: wrap; }
  .header .info-pill { background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-radius: 20px; padding: 0.4rem 1rem; font-size: 0.8rem; color: var(--text-dim); }
  .header .info-pill strong { color: var(--text); }

  .container { max-width: 1400px; margin: 0 auto; padding: 2rem 4rem; }

  .score-dashboard { display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; margin: 2rem 0; }
  .risk-gauge { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; text-align: center; position: relative; }
  .risk-gauge .gauge-value { font-size: 5rem; font-weight: 900; line-height: 1; }
  .risk-gauge .gauge-label { color: var(--text-dim); font-size: 0.75rem; letter-spacing: 0.2em; text-transform: uppercase; margin-top: 0.5rem; }
  .risk-gauge.critical .gauge-value { color: var(--critical); text-shadow: 0 0 30px rgba(239,68,68,0.4); }
  .risk-gauge.high .gauge-value { color: var(--high); }
  .risk-gauge.medium .gauge-value { color: var(--medium); }

  .severity-bars { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; }
  .severity-row { display: flex; align-items: center; gap: 1rem; margin: 0.75rem 0; }
  .severity-row .label { width: 80px; font-size: 0.8rem; letter-spacing: 0.1em; }
  .severity-row .bar-container { flex: 1; background: var(--surface2); border-radius: 4px; height: 20px; overflow: hidden; }
  .severity-row .bar { height: 100%; border-radius: 4px; transition: width 0.8s ease; display: flex; align-items: center; padding: 0 0.5rem; font-size: 0.75rem; font-weight: bold; }
  .bar.critical { background: linear-gradient(90deg, rgba(239,68,68,0.8), rgba(239,68,68,0.4)); color: #fff; }
  .bar.high     { background: linear-gradient(90deg, rgba(249,115,22,0.8), rgba(249,115,22,0.4)); color: #fff; }
  .bar.medium   { background: linear-gradient(90deg, rgba(234,179,8,0.8), rgba(234,179,8,0.4)); color: #000; }
  .bar.low      { background: linear-gradient(90deg, rgba(59,130,246,0.8), rgba(59,130,246,0.4)); color: #fff; }
  .bar.info     { background: linear-gradient(90deg, rgba(6,182,212,0.8), rgba(6,182,212,0.4)); color: #fff; }
  .severity-row .count { width: 40px; text-align: right; font-weight: bold; }

  .section-header { display: flex; align-items: center; gap: 1rem; margin: 2.5rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }
  .section-header h2 { font-size: 1rem; letter-spacing: 0.2em; text-transform: uppercase; color: var(--low); }
  .section-header .count-badge { background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.3); color: var(--low); border-radius: 20px; padding: 0.1rem 0.6rem; font-size: 0.75rem; }

  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; margin: 0.75rem 0; border-left: 4px solid; position: relative; transition: transform 0.2s; }
  .finding:hover { transform: translateX(4px); }
  .finding.CRITICAL { border-left-color: var(--critical); }
  .finding.HIGH     { border-left-color: var(--high); }
  .finding.MEDIUM   { border-left-color: var(--medium); }
  .finding.LOW      { border-left-color: var(--low); }
  .finding.INFO     { border-left-color: var(--info); }

  .finding-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .sev-badge { padding: 0.2rem 0.75rem; border-radius: 20px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em; }
  .badge-CRITICAL { background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }
  .badge-HIGH     { background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }
  .badge-MEDIUM   { background: rgba(234,179,8,0.2); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }
  .badge-LOW      { background: rgba(59,130,246,0.2); color: var(--low); border: 1px solid rgba(59,130,246,0.3); }
  .badge-INFO     { background: rgba(6,182,212,0.2); color: var(--info); border: 1px solid rgba(6,182,212,0.3); }

  .cat-badge { background: rgba(124,58,237,0.1); color: #a78bfa; border: 1px solid rgba(124,58,237,0.3); padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.7rem; }
  .cve-tag { background: rgba(239,68,68,0.05); color: var(--critical); border: 1px solid rgba(239,68,68,0.2); padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }
  .finding-title { font-size: 0.95rem; font-weight: bold; color: var(--text); }
  .finding-detail { color: var(--text-dim); font-size: 0.8rem; margin-top: 0.5rem; }
  .finding-exploit { background: var(--surface2); border: 1px solid rgba(34,197,94,0.2); border-radius: 6px; padding: 0.6rem 1rem; margin-top: 0.75rem; font-size: 0.78rem; color: var(--success); font-family: 'JetBrains Mono', monospace; word-break: break-all; }
  .finding-exploit::before { content: '$ '; color: var(--text-dim); }

  .finding .evidence { background: rgba(6,182,212,0.05); border: 1px solid rgba(6,182,212,0.15); border-radius: 6px; padding: 0.5rem 0.75rem; margin-top: 0.65rem; font-size: 0.78rem; }
  .finding .evidence-title { font-weight: 700; color: var(--info); margin-bottom: 0.35rem; font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; }
  .finding .evidence ul { list-style: none; padding: 0; margin: 0; }
  .finding .evidence li { padding: 0.12rem 0; color: var(--text-dim); }
  .finding .evidence li::before { content: '▸ '; color: var(--info); }
  .finding .cred-preview { background: rgba(168,85,247,0.06); border: 1px solid rgba(168,85,247,0.2); border-radius: 6px; padding: 0.5rem 0.75rem; margin-top: 0.65rem; font-size: 0.78rem; }
  .finding .cred-preview-title { font-weight: 700; color: #a78bfa; margin-bottom: 0.35rem; font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; }
  .finding .cred-preview ul { list-style: none; padding: 0; margin: 0; }
  .finding .cred-preview li { padding: 0.12rem 0; color: var(--text-dim); word-break: break-word; }
  .finding .cred-preview li::before { content: '▸ '; color: #a78bfa; }
  .finding .remediation { background: rgba(34,197,94,0.05); border: 1px solid rgba(34,197,94,0.15); border-radius: 6px; padding: 0.5rem 0.75rem; margin-top: 0.65rem; font-size: 0.78rem; }
  .finding .remediation-title { font-weight: 700; color: var(--success); margin-bottom: 0.25rem; font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; }
  .finding .remediation-text { color: var(--text-dim); }
  .finding .references { margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-dim); }
  .finding .finding-scoring { background: var(--surface2); border-radius: 6px; padding: 0.4rem 0.65rem; margin-top: 0.5rem; font-size: 0.75rem; color: var(--info); }

  .system-info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem; margin: 1.5rem 0; }
  .info-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; }
  .info-card h3 { font-size: 0.7rem; letter-spacing: 0.2em; text-transform: uppercase; color: var(--text-dim); margin-bottom: 1rem; }
  .info-row { display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
  .info-row:last-child { border-bottom: none; }
  .info-row .key { color: var(--text-dim); }
  .info-row .val { color: var(--text); font-weight: 500; }

  .tag-container { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }
  .tag { background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.7rem; color: var(--text-dim); }

  .footer { text-align: center; color: var(--text-muted); padding: 3rem 2rem 2rem; font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 4rem; }
  .footer a { color: var(--text-dim); text-decoration: none; }

  @media (max-width: 768px) {
    .container { padding: 1rem; }
    .header { padding: 2rem 1rem; }
    .score-dashboard { grid-template-columns: 1fr; }
    .system-info-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="topbar">
  <span class="brand">π LinuxPi</span>
  <span class="scan-time">Scan: {{SCAN_TIME}} | Host: {{HOSTNAME}}</span>
</div>

<div class="header">
  <h1>π PRIVILEGE ESCALATION REPORT
    <span>LinuxPi · Linux Security Assessment | linuxpi v{{TOOL_VERSION}} | {{AUTHOR_NAME}}</span>
  </h1>
  <div class="target-info">
    <div class="info-pill"><strong>Host:</strong> {{HOSTNAME}}</div>
    <div class="info-pill"><strong>OS:</strong> {{DISTRO}} {{DISTRO_VER}}</div>
    <div class="info-pill"><strong>Kernel:</strong> {{KERNEL}}</div>
    <div class="info-pill"><strong>User:</strong> {{CURRENT_USER}} (UID={{UID}})</div>
    <div class="info-pill"><strong>Arch:</strong> {{ARCH}}</div>
  </div>
</div>

<div class="container">

  <!-- RISK DASHBOARD -->
  <div class="score-dashboard">
    <div class="risk-gauge {{RISK_CLASS}}">
      <div class="gauge-value">{{RISK_SCORE}}</div>
      <div class="gauge-label">Overall Risk Score</div>
    </div>

    <div class="severity-bars">
      <div class="severity-row">
        <span class="label" style="color: var(--critical)">CRITICAL</span>
        <div class="bar-container"><div class="bar critical" style="width: {{CRITICAL_PCT}}%">{{CRITICAL_COUNT}}</div></div>
        <span class="count" style="color: var(--critical)">{{CRITICAL_COUNT}}</span>
      </div>
      <div class="severity-row">
        <span class="label" style="color: var(--high)">HIGH</span>
        <div class="bar-container"><div class="bar high" style="width: {{HIGH_PCT}}%">{{HIGH_COUNT}}</div></div>
        <span class="count" style="color: var(--high)">{{HIGH_COUNT}}</span>
      </div>
      <div class="severity-row">
        <span class="label" style="color: var(--medium)">MEDIUM</span>
        <div class="bar-container"><div class="bar medium" style="width: {{MEDIUM_PCT}}%">{{MEDIUM_COUNT}}</div></div>
        <span class="count" style="color: var(--medium)">{{MEDIUM_COUNT}}</span>
      </div>
      <div class="severity-row">
        <span class="label" style="color: var(--low)">LOW</span>
        <div class="bar-container"><div class="bar low" style="width: {{LOW_PCT}}%">{{LOW_COUNT}}</div></div>
        <span class="count" style="color: var(--low)">{{LOW_COUNT}}</span>
      </div>
      <div class="severity-row">
        <span class="label" style="color: var(--info)">INFO</span>
        <div class="bar-container"><div class="bar info" style="width: {{INFO_PCT}}%">{{INFO_COUNT}}</div></div>
        <span class="count" style="color: var(--info)">{{INFO_COUNT}}</span>
      </div>
    </div>
  </div>

  <!-- SYSTEM INFORMATION -->
  <div class="section-header">
    <h2>System Information</h2>
  </div>
  <div class="system-info-grid">
    <div class="info-card">
      <h3>Host Details</h3>
      <div class="info-row"><span class="key">Hostname</span><span class="val">{{HOSTNAME}}</span></div>
      <div class="info-row"><span class="key">OS</span><span class="val">{{DISTRO}} {{DISTRO_VER}}</span></div>
      <div class="info-row"><span class="key">Kernel</span><span class="val">{{KERNEL}}</span></div>
      <div class="info-row"><span class="key">Architecture</span><span class="val">{{ARCH}}</span></div>
      <div class="info-row"><span class="key">Init System</span><span class="val">{{INIT_SYSTEM}}</span></div>
    </div>
    <div class="info-card">
      <h3>Current Context</h3>
      <div class="info-row"><span class="key">User</span><span class="val">{{CURRENT_USER}}</span></div>
      <div class="info-row"><span class="key">UID / GID</span><span class="val">{{UID}} / {{GID}}</span></div>
      <div class="info-row"><span class="key">Shell</span><span class="val">{{SHELL}}</span></div>
      <div class="info-row"><span class="key">Container</span><span class="val">{{CONTAINER_TYPE}}</span></div>
      <div class="info-row"><span class="key">Cloud</span><span class="val">{{CLOUD_PROVIDER}}</span></div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section-header">
    <h2>Findings</h2>
    <span class="count-badge">{{TOTAL_COUNT}}</span>
  </div>

  {{FINDINGS_HTML}}

</div>

<div class="footer">
  <p>Generated by <strong>LinuxPi (π) v{{TOOL_VERSION}}</strong> on {{SCAN_TIME}}</p>
  <p style="margin-top: 0.5rem;">Developed by <strong>{{AUTHOR_NAME}}</strong> · <a href="mailto:{{AUTHOR_EMAIL}}">{{AUTHOR_EMAIL}}</a> · <a href="{{AUTHOR_LINKEDIN}}" rel="noopener">LinkedIn</a></p>
  <p style="margin-top: 0.5rem;">⚠ For authorized penetration testing and security assessments only. Unauthorized use is prohibited.</p>
  <p style="margin-top: 0.5rem;"><a href="https://github.com/cumakurt/linuxpi">github.com/cumakurt/linuxpi</a></p>
</div>

</body>
</html>
