"""HTML report exporter with professional styling."""

from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime

from jinja2 import Environment, BaseLoader, select_autoescape

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# Professional HTML template with embedded CSS
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - PurpleForge Report</title>
    <style>
        :root {
            --primary-color: #6b21a8;
            --secondary-color: #9333ea;
            --success-color: #22c55e;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
            border-radius: 12px;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .header .meta {
            margin-top: 1.5rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
        }

        .header .meta-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* Cards */
        .card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
            overflow: hidden;
        }

        .card-header {
            background: var(--bg-color);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 1.1rem;
        }

        .card-body {
            padding: 1.5rem;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        th, td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: var(--bg-color);
            font-weight: 600;
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        tr:hover {
            background: var(--bg-color);
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success { background: #dcfce7; color: #166534; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        .badge-purple { background: #f3e8ff; color: #6b21a8; }

        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 2rem;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 0.5rem;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border-color);
        }

        .timeline-item {
            position: relative;
            padding-bottom: 1.5rem;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -1.5rem;
            top: 0.5rem;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--primary-color);
        }

        .timeline-item.evidence::before {
            background: var(--success-color);
        }

        .timeline-time {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }

        .timeline-content {
            background: var(--bg-color);
            padding: 1rem;
            border-radius: 8px;
        }

        /* Code blocks */
        pre, code {
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
        }

        pre {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 1rem 0;
        }

        code {
            background: var(--bg-color);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
        }

        pre code {
            background: none;
            padding: 0;
        }

        /* Stats grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .stat-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* Progress bar */
        .progress-bar {
            height: 8px;
            background: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        /* Collapsible sections */
        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible::after {
            content: ' [+]';
            font-weight: normal;
            color: var(--text-muted);
        }

        .collapsible.active::after {
            content: ' [-]';
        }

        .collapsible-content {
            display: none;
            padding-top: 1rem;
        }

        .collapsible-content.show {
            display: block;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        /* ATT&CK section */
        .attack-technique {
            border-left: 4px solid var(--primary-color);
            padding-left: 1rem;
            margin-bottom: 1.5rem;
        }

        .attack-technique h4 {
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }

        .mitigation-list {
            list-style: none;
            padding: 0;
        }

        .mitigation-list li {
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .mitigation-list li:last-child {
            border-bottom: none;
        }

        /* Print styles */
        @media print {
            body {
                background: white;
            }
            .container {
                max-width: none;
                padding: 0;
            }
            .card {
                box-shadow: none;
                border: 1px solid var(--border-color);
                break-inside: avoid;
            }
            .header {
                background: var(--primary-color);
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>{{ title }}</h1>
            <p class="subtitle">PurpleForge Incident Report</p>
            <div class="meta">
                <div class="meta-item">
                    <strong>Run ID:</strong> {{ run_id }}
                </div>
                <div class="meta-item">
                    <strong>Generated:</strong> {{ generated_at }}
                </div>
                <div class="meta-item">
                    <strong>Status:</strong>
                    <span class="badge {% if status == 'completed' %}badge-success{% else %}badge-warning{% endif %}">
                        {{ status }}
                    </span>
                </div>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ total_steps }}</div>
                <div class="stat-label">Total Steps</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ steps_with_evidence }}</div>
                <div class="stat-label">Steps with Evidence</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ coverage }}%</div>
                <div class="stat-label">Coverage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ timeline_events }}</div>
                <div class="stat-label">Timeline Events</div>
            </div>
        </div>

        <!-- Coverage Progress -->
        <div class="card">
            <div class="card-header">Coverage Progress</div>
            <div class="card-body">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ coverage }}%"></div>
                </div>
                <p style="margin-top: 0.5rem; color: var(--text-muted);">
                    {{ coverage }}% of scenario steps have correlated evidence
                </p>
            </div>
        </div>

        <!-- Target Information -->
        <div class="card">
            <div class="card-header">Target Information</div>
            <div class="card-body">
                <table>
                    <tr>
                        <td><strong>Target URL</strong></td>
                        <td><code>{{ target_url }}</code></td>
                    </tr>
                    <tr>
                        <td><strong>Verification Status</strong></td>
                        <td>
                            <span class="badge {% if verification_status == 'verified' %}badge-success{% else %}badge-warning{% endif %}">
                                {{ verification_status }}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Scenario</strong></td>
                        <td>{{ scenario_name }}</td>
                    </tr>
                    <tr>
                        <td><strong>Category</strong></td>
                        <td><span class="badge badge-purple">{{ category }}</span></td>
                    </tr>
                    <tr>
                        <td><strong>Mode</strong></td>
                        <td><span class="badge badge-info">{{ mode }}</span></td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Steps Executed -->
        <div class="card">
            <div class="card-header collapsible" onclick="toggleCollapsible(this)">Steps Executed</div>
            <div class="card-body collapsible-content show">
                <table>
                    <thead>
                        <tr>
                            <th>Step ID</th>
                            <th>Type</th>
                            <th>Description</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for step in steps %}
                        <tr>
                            <td><code>{{ step.id }}</code></td>
                            <td><span class="badge badge-purple">{{ step.type }}</span></td>
                            <td>{{ step.description }}</td>
                            <td>
                                {% if step.has_evidence %}
                                <span class="badge badge-success">Yes ({{ step.evidence_count }})</span>
                                {% else %}
                                <span class="badge badge-warning">No</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ATT&CK Techniques -->
        {% if attack_techniques %}
        <div class="card">
            <div class="card-header collapsible" onclick="toggleCollapsible(this)">ATT&CK Mapping</div>
            <div class="card-body collapsible-content show">
                {% for technique in attack_techniques %}
                <div class="attack-technique">
                    <h4>{{ technique.id }} - {{ technique.name }}</h4>
                    <p><strong>Tactic:</strong> {{ technique.tactic }}</p>
                    <p>{{ technique.description[:300] }}{% if technique.description|length > 300 %}...{% endif %}</p>

                    {% if technique.mitigations %}
                    <p><strong>Mitigations:</strong></p>
                    <ul class="mitigation-list">
                        {% for m in technique.mitigations[:5] %}
                        <li><strong>{{ m.id }}</strong> - {{ m.name }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    <p><a href="{{ technique.url }}" target="_blank">View on MITRE ATT&CK</a></p>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Timeline -->
        {% if timeline %}
        <div class="card">
            <div class="card-header collapsible" onclick="toggleCollapsible(this)">Event Timeline</div>
            <div class="card-body collapsible-content">
                <div class="timeline">
                    {% for event in timeline[:20] %}
                    <div class="timeline-item {% if event.type == 'evidence' %}evidence{% endif %}">
                        <div class="timeline-time">{{ event.timestamp }}</div>
                        <div class="timeline-content">
                            <strong>{{ event.type|title }}</strong>
                            {% if event.step_id %} - {{ event.step_id }}{% endif %}
                            {% if event.details %}
                            <br><small>{{ event.details }}</small>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                    {% if timeline|length > 20 %}
                    <p style="color: var(--text-muted); font-style: italic;">
                        ... and {{ timeline|length - 20 }} more events
                    </p>
                    {% endif %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Detection Recommendations -->
        <div class="card">
            <div class="card-header collapsible" onclick="toggleCollapsible(this)">Detection Recommendations</div>
            <div class="card-body collapsible-content">
                {{ detection_recommendations | safe }}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by <strong>PurpleForge v{{ tool_version }}</strong></p>
            <p>{{ generated_at }}</p>
            <p style="margin-top: 1rem; font-size: 0.8rem;">
                This report documents a controlled security assessment conducted in a lab environment
                with explicit authorization. All activities were logged and auditable.
            </p>
        </div>
    </div>

    <script>
        function toggleCollapsible(element) {
            element.classList.toggle('active');
            const content = element.nextElementSibling;
            content.classList.toggle('show');
        }
    </script>
</body>
</html>
'''


def export_html(
    report_data: Dict[str, Any],
    output_path: Path,
    include_timeline: bool = True,
) -> Path:
    """
    Export report as styled HTML.

    Args:
        report_data: Report data dictionary
        output_path: Path to write HTML file
        include_timeline: Whether to include event timeline

    Returns:
        Path to created HTML file
    """
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=True),
    )
    template = env.from_string(HTML_TEMPLATE)

    # Prepare template data
    context = {
        "title": report_data.get("scenario_name", "Security Assessment"),
        "run_id": report_data.get("run_id", "unknown"),
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": report_data.get("status", "completed"),
        "total_steps": report_data.get("total_steps", 0),
        "steps_with_evidence": report_data.get("steps_with_evidence", 0),
        "coverage": report_data.get("coverage", 0),
        "timeline_events": len(report_data.get("timeline", [])),
        "target_url": report_data.get("target_url", "N/A"),
        "verification_status": report_data.get("verification_status", "unknown"),
        "scenario_name": report_data.get("scenario_name", "N/A"),
        "category": report_data.get("category", "web"),
        "mode": report_data.get("mode", "assess"),
        "steps": report_data.get("steps", []),
        "attack_techniques": report_data.get("attack_techniques", []),
        "timeline": report_data.get("timeline", []) if include_timeline else [],
        "detection_recommendations": report_data.get("detection_recommendations", ""),
        "tool_version": report_data.get("tool_version", "0.1.0"),
    }

    html_content = template.render(**context)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info(f"HTML report exported to {output_path}")
    return output_path
