"""Self-contained, security-hardened HTML digest renderer."""

from __future__ import annotations

import jinja2

from sloth_soc.schema import ACTION_TEXT_MAP, Brief, DigestMeta, Finding, NarratorOutput

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
  <title>Sloth SOC Digest - {{ brief.date }}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: #1a1a1a;
      background: #f8fafc;
      margin: 0;
      padding: 24px;
    }
    .container {
      max-width: 760px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 32px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .header {
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 0.85rem;
      letter-spacing: 0.05em;
    }
    .badge-urgent { background: #fee2e2; color: #991b1b; }
    .badge-attention { background: #fef3c7; color: #92400e; }
    .badge-quiet { background: #dcfce7; color: #166534; }
    .badge-critical { background: #ef4444; color: #ffffff; }
    .badge-high { background: #f97316; color: #ffffff; }
    .badge-medium { background: #eab308; color: #ffffff; }
    .badge-low { background: #3b82f6; color: #ffffff; }
    .tldr {
      background: #f1f5f9;
      border-left: 4px solid #0284c7;
      padding: 14px 18px;
      border-radius: 0 4px 4px 0;
      margin-bottom: 28px;
      font-size: 1.05rem;
    }
    .finding-card {
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .entity-code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 600;
    }
    .action-box {
      margin-top: 10px;
      padding: 10px;
      background: #f8fafc;
      border-radius: 4px;
      font-size: 0.95rem;
    }
    .footer {
      margin-top: 32px;
      border-top: 1px solid #e2e8f0;
      padding-top: 14px;
      font-size: 0.82rem;
      color: #64748b;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1 style="margin:0; font-size:1.5rem;">Sloth SOC Morning Digest</h1>
        <span class="badge badge-{{ brief.status }}">{{ brief.status | upper }}</span>
      </div>
      <div style="color:#64748b; font-size:0.9rem; margin-top:6px;">
        Host: <strong>{{ meta.host_label }}</strong> | Date: {{ brief.date }} UTC
      </div>
    </div>

    <div class="tldr">
      <strong>TL;DR:</strong> {{ narrator_out.tldr }}
    </div>

    <h2>Needs Your Attention ({{ brief.findings | length }})</h2>
    {% if not brief.findings %}
      <p style="color:#64748b;">No security anomalies requiring administrative attention.</p>
    {% else %}
      {% for f in brief.findings %}
        {% set item = narrator_map.get(f.id) %}
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="badge badge-{{ f.severity }}">{{ f.severity | upper }}</span>
              <span class="entity-code" style="margin-left:8px;">{{ f.entity }}</span>
            </div>
            <span style="font-size:0.85rem; color:#64748b;">{{ f.window }}</span>
          </div>
          <div style="margin-top:6px;">
            <strong>Analysis:</strong> {{ item.explanation if item else f.reasons[0] }}
          </div>
          <div class="action-box">
            <strong>Action:</strong> {{ action_text_map.get(f.action, f.action) }}
          </div>
        </div>
      {% endfor %}
    {% endif %}

    <h2 style="margin-top:28px;">Handled While You Slept ({{ handled_findings | length }})</h2>
    {% if handled_findings %}
      <p>{{ handled_findings | length }} source addresses were dropped or banned overnight.</p>
      <ul>
        {% for h in handled_findings[:6] %}
          <li><span class="entity-code">{{ h.entity }}</span>: {{ h.kind }} (blocked)</li>
        {% endfor %}
      </ul>
    {% else %}
      <p style="color:#64748b;">No automated edge blocks triggered overnight.</p>
    {% endif %}

    <h2 style="margin-top:28px;">Noise Ignored</h2>
    <p style="color:#64748b;">{{ narrator_out.noise_note or "Routine web crawling and health monitoring." }}</p>

    <div class="footer">
      {{ "{:,}".format(meta.raw_lines) }} lines &rarr; {{ meta.attention_items }} items to read
      (lazy ratio {{ "%.0f"|format(meta.lazy_ratio) }}:1) | {{ meta.model or 'template' }} |
      narrator={{ meta.narrator }} retries={{ meta.retries }} latency={{ "%.1f"|format(meta.latency_seconds) }}s |
      parse coverage {{ "%.1f"|format(meta.parse_coverage * 100) }}%
    </div>
  </div>
</body>
</html>
"""


def render_html(
    brief: Brief,
    narrator_out: NarratorOutput,
    meta: DigestMeta,
    handled_findings: list[Finding] | None = None,
) -> str:
    """Render the daily digest into hardened, self-contained HTML with autoescaping and strict CSP."""
    env = jinja2.Environment(
        autoescape=jinja2.select_autoescape(["html", "xml"]),
    )
    template = env.from_string(HTML_TEMPLATE)

    narrator_map = {item.finding_id: item for item in narrator_out.items}

    return template.render(
        brief=brief,
        narrator_out=narrator_out,
        meta=meta,
        handled_findings=handled_findings or [],
        narrator_map=narrator_map,
        action_text_map=ACTION_TEXT_MAP,
    )
