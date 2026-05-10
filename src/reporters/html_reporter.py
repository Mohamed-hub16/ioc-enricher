"""HTML report generator for IOC enrichment results."""

from datetime import datetime
from jinja2 import Environment, BaseLoader
from src.models import EnrichmentResult


def _risk(results: list[EnrichmentResult]) -> tuple[str, int]:
    scores: list[int] = []
    for r in results:
        if not r.success:
            continue
        if r.source == "AbuseIPDB":
            s = r.data.get("abuse_confidence_score")
            if s is not None:
                scores.append(int(s))
        elif r.source == "VirusTotal":
            mal = r.data.get("malicious", 0)
            tot = r.data.get("total_engines", 0)
            if tot:
                scores.append(int(mal / tot * 100))
    if not scores:
        return "INCONNU", 0
    m = max(scores)
    if m >= 75:
        return "CRITIQUE", m
    if m >= 50:
        return "ÉLEVÉ", m
    if m >= 10:
        return "MODÉRÉ", m
    return "FAIBLE", m


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IOC Enrichment Report — {{ generated_at }}</title>
<style>
:root {
  --bg:        #0d1117;
  --bg1:       #161b22;
  --bg2:       #21262d;
  --bg3:       #2d333b;
  --border:    #30363d;
  --border2:   #444c56;
  --text:      #cdd9e5;
  --muted:     #768390;
  --blue:      #539bf5;
  --green:     #57ab5a;
  --yellow:    #c69026;
  --orange:    #e0823d;
  --red:       #e5534b;
  --purple:    #986ee2;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text);
       font-size: 14px; line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }

/* HEADER */
header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem;
         display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 1rem; }
.header-left h1 { font-size: 1.5rem; font-weight: 700; color: var(--blue); letter-spacing: -.3px; }
.header-left .subtitle { color: var(--muted); font-size: .85rem; margin-top: .2rem; }
.header-stats { display: flex; gap: 1.5rem; }
.stat { text-align: right; }
.stat-val { font-size: 1.4rem; font-weight: 700; color: var(--text); }
.stat-lbl { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }

/* SUMMARY TABLE */
.section-title { font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;
                 color: var(--muted); margin-bottom: .75rem; }
.summary-table { width: 100%; border-collapse: collapse; margin-bottom: 2.5rem;
                 border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.summary-table th { background: var(--bg2); color: var(--muted); font-size: .75rem;
                    text-transform: uppercase; letter-spacing: .5px; padding: .6rem 1rem; text-align: left; }
.summary-table td { padding: .6rem 1rem; border-top: 1px solid var(--border); }
.summary-table tr:hover td { background: var(--bg2); }
.mono { font-family: 'Cascadia Code','Fira Code','Consolas', monospace; }

/* BADGES */
.badge { display: inline-block; padding: .15rem .55rem; border-radius: 4px; font-size: .7rem;
         font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
.badge-ip      { background: #1c3a5e; color: #58a6ff; }
.badge-domain  { background: #1a3a2a; color: #57ab5a; }
.badge-hash    { background: #2d2050; color: #986ee2; }

.risk-badge { display: inline-flex; align-items: center; gap: .35rem;
              padding: .25rem .75rem; border-radius: 20px; font-size: .75rem;
              font-weight: 700; letter-spacing: .5px; }
.risk-CRITIQUE { background: rgba(229,83,75,.15);  color: #e5534b; border: 1px solid rgba(229,83,75,.3); }
.risk-ÉLEVÉ    { background: rgba(224,130,61,.15); color: #e0823d; border: 1px solid rgba(224,130,61,.3); }
.risk-MODÉRÉ   { background: rgba(198,144,38,.15); color: #c69026; border: 1px solid rgba(198,144,38,.3); }
.risk-FAIBLE   { background: rgba(87,171,90,.15);  color: #57ab5a; border: 1px solid rgba(87,171,90,.3); }
.risk-INCONNU  { background: rgba(118,131,144,.15);color: #768390; border: 1px solid rgba(118,131,144,.3); }

/* IOC CARD */
.ioc-card { background: var(--bg1); border: 1px solid var(--border); border-radius: 10px;
            margin-bottom: 2rem; overflow: hidden; }
.ioc-card-header { display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
                   padding: 1rem 1.25rem; background: var(--bg2);
                   border-bottom: 1px solid var(--border); }
.ioc-value { font-family: 'Cascadia Code','Fira Code','Consolas',monospace;
             font-size: 1.05rem; color: #f0c000; font-weight: 600; }
.ioc-card-body { padding: 1.25rem; }

/* RISK BAR */
.risk-bar-row { display: flex; align-items: center; gap: .75rem; margin-bottom: 1.25rem; }
.risk-bar-track { flex: 1; height: 6px; background: var(--bg3); border-radius: 3px; overflow: hidden; }
.risk-bar-fill { height: 100%; border-radius: 3px; }
.fill-CRITIQUE { background: linear-gradient(90deg, #e5534b, #ff6b60); }
.fill-ÉLEVÉ    { background: linear-gradient(90deg, #e0823d, #ff9d5c); }
.fill-MODÉRÉ   { background: linear-gradient(90deg, #c69026, #f0b030); }
.fill-FAIBLE   { background: linear-gradient(90deg, #57ab5a, #7dd880); }
.fill-INCONNU  { background: var(--border2); }

/* SOURCE GRID */
.sources-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
.source-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.source-card-header { display: flex; align-items: center; gap: .5rem;
                      padding: .6rem 1rem; border-bottom: 1px solid var(--border); }
.source-dot { width: 8px; height: 8px; border-radius: 50%; }
.dot-abuseipdb  { background: #e5534b; }
.dot-virustotal { background: #3394d4; }
.dot-urlscan    { background: #8e5cf8; }
.source-name { font-weight: 700; font-size: .8rem; color: var(--text); }
.source-card-body { padding: .75rem 1rem; }
.source-error { color: var(--red); font-style: italic; font-size: .8rem; }

/* DATA TABLE */
.data-table { width: 100%; font-size: .8rem; }
.data-table tr td { padding: .3rem 0; vertical-align: top; }
.data-table td:first-child { color: var(--muted); padding-right: .75rem; width: 45%; }
.data-table td:last-child  { color: var(--text); word-break: break-all; }

/* SCORES */
.big-score { font-size: 2rem; font-weight: 900; line-height: 1; }
.score-crit { color: var(--red); }
.score-high { color: var(--orange); }
.score-med  { color: var(--yellow); }
.score-low  { color: var(--green); }

/* VT BAR */
.vt-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: .4rem 0; }
.vt-seg-mal { background: var(--red); }
.vt-seg-sus { background: var(--orange); }
.vt-seg-ok  { background: var(--bg3); }

/* SCAN LIST */
.scan-list { list-style: none; }
.scan-list li { padding: .3rem 0; border-bottom: 1px solid var(--border); font-size: .78rem; }
.scan-list li:last-child { border-bottom: none; }
.scan-malicious { color: var(--red); }
.scan-clean     { color: var(--green); }
.scan-url       { color: var(--muted); font-family: monospace; word-break: break-all; }

/* UNKNOWN */
.unknown-box { margin-top: 2rem; padding: 1rem; background: var(--bg1);
               border: 1px solid var(--border); border-radius: 8px; }
.unknown-box ul { margin-top: .5rem; padding-left: 1.25rem; color: var(--muted); }

/* AI SYNTHESIS BOX */
.ai-box { background: linear-gradient(135deg, #1a1630 0%, #12101e 100%);
          border: 1px solid #3d2d6e; border-radius: 8px;
          padding: 1rem 1.25rem; margin-bottom: 1.25rem; }
.ai-box-header { display: flex; justify-content: space-between; align-items: center;
                 margin-bottom: .65rem; }
.ai-label { font-size: .7rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 1px; color: #986ee2; }
.ai-text { color: #cdd9e5; font-size: .875rem; line-height: 1.65; }
.copy-btn { background: transparent; border: 1px solid #3d2d6e; color: #986ee2;
            font-size: .7rem; padding: .2rem .65rem; border-radius: 4px;
            cursor: pointer; transition: all .15s; }
.copy-btn:hover { background: #3d2d6e; color: #c5a9f5; }

/* FOOTER */
footer { border-top: 1px solid var(--border); margin-top: 3rem; padding-top: 1rem;
         color: var(--muted); font-size: .75rem;
         display: flex; justify-content: space-between; flex-wrap: wrap; gap: .5rem; }
</style>
<script>
function copyAI(btn) {
  var text = btn.closest('.ai-box').querySelector('.ai-text').innerText;
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = 'Copié !';
    setTimeout(function() { btn.textContent = 'Copier'; }, 2000);
  });
}
</script>
</head>
<body>
<div class="container">

<!-- HEADER -->
<header>
  <div class="header-left">
    <h1>IOC Enrichment Report</h1>
    <div class="subtitle">{{ generated_at }} &nbsp;·&nbsp; AbuseIPDB · VirusTotal · urlscan.io</div>
  </div>
  <div class="header-stats">
    <div class="stat">
      <div class="stat-val">{{ total_iocs }}</div>
      <div class="stat-lbl">IOC(s)</div>
    </div>
    {% set critiques = ioc_risks.values() | selectattr('0', 'equalto', 'CRITIQUE') | list | length %}
    {% set eleves    = ioc_risks.values() | selectattr('0', 'equalto', 'ÉLEVÉ')    | list | length %}
    <div class="stat">
      <div class="stat-val" style="color:var(--red)">{{ critiques }}</div>
      <div class="stat-lbl">Critiques</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:var(--orange)">{{ eleves }}</div>
      <div class="stat-lbl">Élevés</div>
    </div>
  </div>
</header>

<!-- SUMMARY TABLE -->
<div class="section-title">Résumé</div>
<table class="summary-table">
  <thead>
    <tr>
      <th>IOC</th><th>Type</th><th>Risque</th>
      <th>AbuseIPDB</th><th>VirusTotal</th><th>urlscan.io</th>
    </tr>
  </thead>
  <tbody>
  {% for ioc_value, results in grouped.items() %}
    {% set risk_level, risk_score = ioc_risks[ioc_value] %}
    {% set ioc = results[0].ioc %}
    <tr>
      <td class="mono">{{ ioc_value }}</td>
      <td><span class="badge badge-{{ ioc.type }}">{{ ioc.type }}</span></td>
      <td><span class="risk-badge risk-{{ risk_level }}">{{ risk_level }}</span></td>
      {% set abuse = results | selectattr('source', 'equalto', 'AbuseIPDB') | list %}
      <td>
        {% if abuse and abuse[0].success %}
          {% set s = abuse[0].data.abuse_confidence_score %}
          <span class="{{ 'score-crit' if s >= 75 else 'score-high' if s >= 50 else 'score-med' if s >= 10 else 'score-low' }}">{{ s }}%</span>
        {% else %}<span style="color:var(--muted)">—</span>{% endif %}
      </td>
      {% set vt = results | selectattr('source', 'equalto', 'VirusTotal') | list %}
      <td>
        {% if vt and vt[0].success %}
          <span class="{{ 'score-crit' if vt[0].data.malicious >= 10 else 'score-high' if vt[0].data.malicious >= 3 else 'score-med' if vt[0].data.malicious >= 1 else 'score-low' }}">
            {{ vt[0].data.malicious }}/{{ vt[0].data.total_engines }}
          </span>
        {% else %}<span style="color:var(--muted)">—</span>{% endif %}
      </td>
      {% set us = results | selectattr('source', 'equalto', 'urlscan.io') | list %}
      <td>
        {% if us and us[0].success %}
          {{ us[0].data.total_scans }} scan(s)
          {% if us[0].data.malicious_count > 0 %}
            · <span class="score-crit">{{ us[0].data.malicious_count }} malveillant(s)</span>
          {% endif %}
        {% else %}<span style="color:var(--muted)">—</span>{% endif %}
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>

<!-- DETAILED IOC CARDS -->
{% for ioc_value, results in grouped.items() %}
  {% set risk_level, risk_score = ioc_risks[ioc_value] %}
  {% set ioc = results[0].ioc %}

<div class="ioc-card">
  <div class="ioc-card-header">
    <span class="badge badge-{{ ioc.type }}">{{ ioc.type }}</span>
    <span class="ioc-value">{{ ioc_value }}</span>
    <span class="risk-badge risk-{{ risk_level }}">&#9679; {{ risk_level }}</span>
  </div>

  <div class="ioc-card-body">
    <!-- Risk bar -->
    <div class="risk-bar-row">
      <div style="font-size:.75rem;color:var(--muted);width:80px">Score : {{ risk_score }}%</div>
      <div class="risk-bar-track">
        <div class="risk-bar-fill fill-{{ risk_level }}" style="width:{{ risk_score }}%"></div>
      </div>
    </div>

    <!-- AI synthesis -->
    {% if synthesis and synthesis.get(ioc_value) %}
    <div class="ai-box">
      <div class="ai-box-header">
        <span class="ai-label">&#9889; Analyse IA — Groq / LLaMA 3.3</span>
        <button class="copy-btn" onclick="copyAI(this)">Copier</button>
      </div>
      <div class="ai-text">{{ synthesis[ioc_value] | e }}</div>
    </div>
    {% endif %}

    <!-- Sources grid -->
    <div class="sources-grid">

      {# AbuseIPDB #}
      {% set abuse_list = results | selectattr('source', 'equalto', 'AbuseIPDB') | list %}
      {% if abuse_list %}{% set r = abuse_list[0] %}
      <div class="source-card">
        <div class="source-card-header">
          <span class="source-dot dot-abuseipdb"></span>
          <span class="source-name">AbuseIPDB</span>
        </div>
        <div class="source-card-body">
          {% if r.error %}<div class="source-error">{{ r.error }}</div>
          {% else %}
            {% set s = r.data.abuse_confidence_score %}
            <div class="big-score {{ 'score-crit' if s >= 75 else 'score-high' if s >= 50 else 'score-med' if s >= 10 else 'score-low' }}">{{ s }}%</div>
            <div style="color:var(--muted);font-size:.75rem;margin-bottom:.75rem">confiance d'abus</div>
            <table class="data-table">
              <tr><td>ISP</td><td>{{ r.data.isp or '—' }}</td></tr>
              <tr><td>Pays</td><td>{{ r.data.country_name or r.data.country_code or '—' }}</td></tr>
              <tr><td>Domaine</td><td>{{ r.data.domain or '—' }}</td></tr>
              <tr><td>Usage</td><td>{{ r.data.usage_type or '—' }}</td></tr>
              <tr><td>Signalements</td><td>{{ r.data.total_reports or 0 }}</td></tr>
              <tr><td>Sources distinctes</td><td>{{ r.data.num_distinct_users or '—' }}</td></tr>
              <tr><td>Dernier rapport</td><td>{{ (r.data.last_reported_at or '—')[:10] }}</td></tr>
              <tr><td>Whitelisted</td><td>{{ 'Oui' if r.data.is_whitelisted else 'Non' }}</td></tr>
            </table>
            {% if r.data.abuse_categories %}
            <div style="margin-top:.6rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Catégories signalées</div>
            <div style="margin-top:.3rem;display:flex;flex-wrap:wrap;gap:.3rem">
              {% for cat in r.data.abuse_categories %}
              <span style="background:rgba(229,83,75,.12);color:#e5534b;border:1px solid rgba(229,83,75,.25);padding:.1rem .45rem;border-radius:4px;font-size:.7rem">{{ cat }}</span>
              {% endfor %}
            </div>
            {% endif %}
          {% endif %}
        </div>
      </div>
      {% endif %}

      {# VirusTotal #}
      {% set vt_list = results | selectattr('source', 'equalto', 'VirusTotal') | list %}
      {% if vt_list %}{% set r = vt_list[0] %}
      <div class="source-card">
        <div class="source-card-header">
          <span class="source-dot dot-virustotal"></span>
          <span class="source-name">VirusTotal</span>
        </div>
        <div class="source-card-body">
          {% if r.error %}<div class="source-error">{{ r.error }}</div>
          {% else %}
            {% set mal = r.data.malicious %}{% set tot = r.data.total_engines %}
            <div class="big-score {{ 'score-crit' if mal >= 10 else 'score-high' if mal >= 3 else 'score-med' if mal >= 1 else 'score-low' }}">
              {{ mal }}<span style="font-size:1rem;font-weight:400">/{{ tot }}</span>
            </div>
            <div style="color:var(--muted);font-size:.75rem;margin-bottom:.4rem">moteurs de détection</div>
            {% if tot > 0 %}
            <div class="vt-bar">
              <div class="vt-seg-mal" style="width:{{ (mal/tot*100)|round(1) }}%"></div>
              <div class="vt-seg-sus" style="width:{{ (r.data.suspicious/tot*100)|round(1) }}%"></div>
              <div class="vt-seg-ok"  style="width:{{ ((tot-mal-r.data.suspicious)/tot*100)|round(1) }}%"></div>
            </div>
            {% endif %}
            <table class="data-table" style="margin-top:.5rem">
              {% if r.data.get('country') %}<tr><td>Pays</td><td>{{ r.data.country }}</td></tr>{% endif %}
              {% if r.data.get('as_owner') %}<tr><td>AS Owner</td><td>{{ r.data.as_owner }}</td></tr>{% endif %}
              {% if r.data.get('asn') %}<tr><td>ASN</td><td>AS{{ r.data.asn }}</td></tr>{% endif %}
              {% if r.data.get('network') %}<tr><td>Réseau</td><td>{{ r.data.network }}</td></tr>{% endif %}
              {% if r.data.get('registrar') %}<tr><td>Registrar</td><td>{{ r.data.registrar }}</td></tr>{% endif %}
              {% if r.data.get('meaningful_name') %}<tr><td>Nom</td><td>{{ r.data.meaningful_name }}</td></tr>{% endif %}
              {% if r.data.get('type_description') %}<tr><td>Type</td><td>{{ r.data.type_description }}</td></tr>{% endif %}
              {% if r.data.get('md5') %}<tr><td>MD5</td><td class="mono" style="font-size:.7rem">{{ r.data.md5 }}</td></tr>{% endif %}
              <tr><td>Réputation</td><td>{{ r.data.reputation if r.data.reputation is not none else '—' }}</td></tr>
              {% if r.data.votes_malicious or r.data.votes_harmless %}<tr><td>Votes</td><td><span style="color:var(--red)">{{ r.data.votes_malicious }} malveillant</span> / <span style="color:var(--green)">{{ r.data.votes_harmless }} clean</span></td></tr>{% endif %}
              {% if r.data.tags %}<tr><td>Tags</td><td>{{ r.data.tags | join(', ') }}</td></tr>{% endif %}
            </table>
            {% if r.data.threat_labels %}
            <div style="margin-top:.6rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Labels de menace</div>
            <div style="margin-top:.3rem;display:flex;flex-wrap:wrap;gap:.3rem">
              {% for lbl in r.data.threat_labels %}
              <span style="background:rgba(51,148,212,.12);color:#539bf5;border:1px solid rgba(51,148,212,.25);padding:.1rem .45rem;border-radius:4px;font-size:.7rem">{{ lbl }}</span>
              {% endfor %}
            </div>
            {% endif %}
            {% if r.data.malicious_vendors %}
            <div style="margin-top:.6rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Éditeurs ayant détecté</div>
            <div style="margin-top:.3rem;color:var(--text);font-size:.75rem;line-height:1.6">{{ r.data.malicious_vendors | join(' · ') }}</div>
            {% endif %}
            {% if r.data.get('crowdsourced_context') %}
            <div style="margin-top:.8rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Contexte communautaire</div>
            {% for ctx in r.data.crowdsourced_context %}
            <div style="margin-top:.4rem;background:var(--bg3);border-radius:6px;padding:.5rem .75rem;font-size:.76rem">
              <span style="font-weight:700;color:var(--blue)">{{ ctx.source }}</span>
              {% if ctx.severity %}<span style="margin-left:.4rem;font-size:.65rem;padding:.1rem .35rem;border-radius:3px;background:rgba(229,83,75,.15);color:#e5534b">{{ ctx.severity }}</span>{% endif %}
              {% if ctx.timestamp %}<span style="margin-left:.4rem;color:var(--muted)">{{ ctx.timestamp }}</span>{% endif %}
              {% if ctx.title %}<div style="margin-top:.2rem;color:var(--text)">{{ ctx.title }}</div>{% endif %}
              {% if ctx.details %}<div style="margin-top:.2rem;color:var(--muted);font-size:.72rem">{{ ctx.details }}</div>{% endif %}
            </div>
            {% endfor %}
            {% endif %}
            {% if r.data.get('ids_rules') %}
            <div style="margin-top:.8rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Règles IDS/IPS matchées ({{ r.data.ids_rules | length }})</div>
            <div style="margin-top:.3rem">
              {% for rule in r.data.ids_rules %}
              <div style="padding:.25rem 0;border-bottom:1px solid var(--border);font-size:.74rem">
                <span style="color:var(--purple)">{{ rule.rule_source }}</span>
                {% if rule.severity %}<span style="margin-left:.35rem;font-size:.65rem;color:{% if rule.severity|lower == 'high' or rule.severity|lower == 'critical' %}var(--red){% elif rule.severity|lower == 'medium' %}var(--orange){% else %}var(--muted){% endif %}">{{ rule.severity }}</span>{% endif %}
                <span style="margin-left:.35rem;color:var(--text)">{{ rule.rule_msg or rule.rule_name }}</span>
              </div>
              {% endfor %}
            </div>
            {% endif %}
            {% if r.data.get('communicating_files') %}
            <div style="margin-top:.8rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Fichiers associés (communiquant avec l'IP)</div>
            {% for f in r.data.communicating_files %}
            <div style="margin-top:.3rem;background:var(--bg3);border-radius:5px;padding:.4rem .65rem;font-size:.74rem">
              <span class="{{ 'score-crit' if f.malicious >= 10 else 'score-high' if f.malicious >= 3 else 'score-med' if f.malicious >= 1 else 'score-low' }}">{{ f.malicious }}/{{ f.total }}</span>
              <span style="margin-left:.5rem;color:var(--text)">{{ f.name }}</span>
              {% if f.type and f.type != '—' %}<span style="margin-left:.4rem;color:var(--muted)">({{ f.type }})</span>{% endif %}
              <div style="color:var(--muted);font-size:.68rem;margin-top:.1rem;font-family:monospace">{{ f.sha256 }}</div>
            </div>
            {% endfor %}
            {% endif %}
          {% endif %}
        </div>
      </div>
      {% endif %}

      {# urlscan.io #}
      {% set us_list = results | selectattr('source', 'equalto', 'urlscan.io') | list %}
      {% if us_list %}{% set r = us_list[0] %}
      <div class="source-card">
        <div class="source-card-header">
          <span class="source-dot dot-urlscan"></span>
          <span class="source-name">urlscan.io</span>
        </div>
        <div class="source-card-body">
          {% if r.error %}<div class="source-error">{{ r.error }}</div>
          {% else %}
            <div class="big-score {{ 'score-crit' if r.data.malicious_count > 0 else 'score-low' }}">
              {{ r.data.total_scans }}
            </div>
            <div style="color:var(--muted);font-size:.75rem;margin-bottom:.75rem">
              scan(s) · {{ r.data.malicious_count }} malveillant(s)
            </div>
            {% if r.data.recent_scans %}
            <div style="font-size:.72rem;color:var(--muted);margin-bottom:.3rem;text-transform:uppercase;letter-spacing:.5px">Scans récents</div>
            <ul class="scan-list">
              {% for s in r.data.recent_scans %}
              <li>
                <span class="{{ 'scan-malicious' if s.malicious else 'scan-clean' }}">
                  {{ '⚠ MALVEILLANT' if s.malicious else '✓ Propre' }}
                </span>
                {% if s.score %} · score {{ s.score }}{% endif %}
                {% if s.time %}<br><span class="scan-url">{{ (s.time or '')[:10] }}</span>{% endif %}
                {% if s.url %}<br><span class="scan-url">{{ (s.url or '')[:60] }}{% if (s.url or '')|length > 60 %}…{% endif %}</span>{% endif %}
                {% if s.tags %}<br><span style="color:var(--purple)">{{ s.tags|join(', ') }}</span>{% endif %}
              </li>
              {% endfor %}
            </ul>
            {% else %}
            <div style="color:var(--muted);font-size:.8rem">Aucun scan récent.</div>
            {% endif %}
          {% endif %}
        </div>
      </div>
      {% endif %}

    </div>{# /sources-grid #}
  </div>{# /ioc-card-body #}
</div>{# /ioc-card #}
{% endfor %}

{% if unknown %}
<div class="unknown-box">
  <div class="section-title">Entrées non reconnues (ignorées)</div>
  <ul>{% for u in unknown %}<li>{{ u }}</li>{% endfor %}</ul>
</div>
{% endif %}

<footer>
  <span>ioc-enricher · AbuseIPDB · VirusTotal · urlscan.io</span>
  <span>{{ generated_at }}</span>
</footer>

</div>
</body>
</html>
"""


def render(
    results: list[EnrichmentResult],
    unknown: list[str] | None = None,
    synthesis: dict[str, str | None] | None = None,
) -> str:
    grouped: dict[str, list[EnrichmentResult]] = {}
    for r in results:
        grouped.setdefault(r.ioc.value, []).append(r)

    ioc_risks = {v: _risk(rs) for v, rs in grouped.items()}

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_TEMPLATE)
    return tmpl.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_iocs=len(grouped),
        grouped=grouped,
        ioc_risks=ioc_risks,
        unknown=unknown or [],
        synthesis=synthesis or {},
    )
