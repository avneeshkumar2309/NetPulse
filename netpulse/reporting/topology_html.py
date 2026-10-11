"""
Interactive Network Topology & Security Audit Report Generator.
Outputs a beautiful, interactive, single-file HTML report with force-directed
network visualization, device cards, and security risk diagnostics.
"""

import json
from pathlib import Path
from typing import Any


def generate_topology_html(scan_result: Any, output_path: str) -> str:
    """
    Generate an interactive HTML report containing a dynamic network topology graph
    and a searchable security audit dashboard.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    scan_dict = scan_result.to_dict()
    data_json = json.dumps(scan_dict)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetPulse Network Topology & Security Audit - {scan_result.target}</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #151d30;
      --border: #23304d;
      --accent: #00d2ff;
      --accent-grad: linear-gradient(135deg, #00d2ff 0%, #00f2fe 100%);
      --text: #e2e8f0;
      --text-muted: #8899b5;
      --green: #10b981;
      --yellow: #f59e0b;
      --red: #ef4444;
      --purple: #8b5cf6;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 16px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .logo-group {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .logo-badge {{
      background: var(--accent-grad);
      color: #0b0f19;
      font-weight: 900;
      font-size: 1.1rem;
      padding: 6px 12px;
      border-radius: 8px;
      letter-spacing: 1px;
    }}
    .title-group h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
    }}
    .title-group p {{
      font-size: 0.82rem;
      color: var(--text-muted);
    }}
    .header-stats {{
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .stat-pill {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      padding: 6px 16px;
      border-radius: 20px;
      font-size: 0.85rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .stat-value {{
      font-weight: bold;
      color: var(--accent);
    }}
    .grade-badge {{
      display: inline-block;
      width: 26px;
      height: 26px;
      line-height: 26px;
      text-align: center;
      border-radius: 50%;
      font-weight: bold;
      color: white;
    }}
    .grade-A {{ background-color: var(--green); }}
    .grade-B {{ background-color: #3b82f6; }}
    .grade-C {{ background-color: var(--yellow); }}
    .grade-D {{ background-color: #f97316; }}
    .grade-F {{ background-color: var(--red); }}

    .main-container {{
      display: flex;
      flex: 1;
      height: calc(100vh - 80px);
      overflow: hidden;
    }}
    #topology {{
      flex: 1;
      height: 100%;
      background: radial-gradient(circle at center, #131c33 0%, #0b0f19 80%);
      position: relative;
    }}
    .sidebar {{
      width: 460px;
      background: var(--card-bg);
      border-left: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      height: 100%;
      transition: all 0.3s ease;
    }}
    .sidebar-header {{
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .sidebar-header h2 {{
      font-size: 1.1rem;
      font-weight: 600;
    }}
    .search-box {{
      padding: 12px 20px;
      border-bottom: 1px solid var(--border);
    }}
    .search-box input {{
      width: 100%;
      background: #0b0f19;
      border: 1px solid var(--border);
      color: white;
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 0.85rem;
      outline: none;
    }}
    .search-box input:focus {{
      border-color: var(--accent);
    }}
    .sidebar-content {{
      flex: 1;
      overflow-y: auto;
      padding: 16px 20px;
    }}
    .host-card {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 14px;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .host-card:hover, .host-card.selected {{
      border-color: var(--accent);
      background: rgba(0, 210, 255, 0.05);
    }}
    .host-card-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    .host-ip {{
      font-weight: 700;
      color: #fff;
      font-size: 1rem;
    }}
    .host-vendor {{
      font-size: 0.8rem;
      color: var(--yellow);
      margin-bottom: 4px;
    }}
    .host-os {{
      font-size: 0.78rem;
      color: var(--text-muted);
    }}
    .port-chip {{
      display: inline-block;
      background: #1f2a44;
      color: #38bdf8;
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 4px;
      margin-right: 4px;
      margin-top: 6px;
    }}
    .details-panel {{
      display: none;
      padding: 16px 20px;
      overflow-y: auto;
      flex: 1;
    }}
    .details-title {{
      font-size: 1.2rem;
      font-weight: bold;
      color: white;
      margin-bottom: 6px;
    }}
    .details-meta {{
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 16px;
      line-height: 1.5;
    }}
    .details-meta span {{
      color: var(--text);
      font-weight: 500;
    }}
    .issue-item {{
      background: rgba(239, 68, 68, 0.08);
      border-left: 3px solid var(--red);
      padding: 10px 12px;
      margin-bottom: 10px;
      border-radius: 0 6px 6px 0;
      font-size: 0.85rem;
    }}
    .issue-item.Critical {{ border-color: var(--red); background: rgba(239, 68, 68, 0.12); }}
    .issue-item.High {{ border-color: #f97316; background: rgba(249, 115, 22, 0.1); }}
    .issue-item.Medium {{ border-color: var(--yellow); background: rgba(245, 158, 11, 0.1); }}
    .issue-item.Low {{ border-color: #38bdf8; background: rgba(56, 189, 248, 0.1); }}
    .issue-title {{
      font-weight: bold;
      margin-bottom: 4px;
      color: white;
    }}
    .issue-rec {{
      color: var(--text-muted);
      font-size: 0.8rem;
    }}
    .port-table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 0.82rem;
    }}
    .port-table th, .port-table td {{
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    .port-table th {{
      color: var(--text-muted);
      font-weight: 600;
    }}
    .btn-back {{
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
      margin-bottom: 14px;
    }}
    .btn-back:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}
  </style>
</head>
<body>
  <header>
    <div class="logo-group">
      <div class="logo-badge">NETPULSE</div>
      <div class="title-group">
        <h1>Network Topology & Security Diagnostics</h1>
        <p>Target: <strong>{scan_result.target}</strong> | Generated: {scan_result.timestamp}</p>
      </div>
    </div>
    <div class="header-stats">
      <div class="stat-pill">
        Live Hosts: <span class="stat-value">{len(scan_result.hosts)}</span>
      </div>
      <div class="stat-pill">
        Scan Duration: <span class="stat-value">{scan_result.duration_seconds}s</span>
      </div>
      <div class="stat-pill">
        Security Posture: 
        <span class="stat-value">{scan_result.network_posture_score}/100</span>
        <span class="grade-badge grade-{scan_result.network_posture_grade}">{scan_result.network_posture_grade}</span>
      </div>
    </div>
  </header>

  <div class="main-container">
    <div id="topology"></div>

    <div class="sidebar">
      <div class="sidebar-header">
        <h2 id="sidebar-title">Host Inventory</h2>
        <span id="host-count" style="font-size: 0.8rem; color: var(--text-muted);">{len(scan_result.hosts)} active nodes</span>
      </div>

      <div class="search-box">
        <input type="text" id="host-search" placeholder="Filter by IP, vendor, service, or port...">
      </div>

      <div class="sidebar-content" id="host-list">
        <!-- Generated by JS -->
      </div>

      <div class="details-panel" id="details-panel">
        <button class="btn-back" id="back-btn">← Back to Host List</button>
        <div id="details-body"></div>
      </div>
    </div>
  </div>

  <script>
    const scanData = {data_json};

    // Prepare Vis.js nodes & edges
    const nodes = [];
    const edges = [];

    // Central Network Hub / Gateway
    nodes.push({{
      id: "hub",
      label: "Gateway\\n" + scanData.target,
      shape: "hexagon",
      color: {{
        background: "#00d2ff",
        border: "#ffffff"
      }},
      font: {{ color: "#ffffff", size: 14, face: "sans-serif" }},
      size: 26
    }});

    const gradeColors = {{
      "A": "#10b981",
      "B": "#3b82f6",
      "C": "#f59e0b",
      "D": "#f97316",
      "F": "#ef4444"
    }};

    scanData.hosts.forEach((h, idx) => {{
      const hostId = "host_" + idx;
      const openCount = h.ports.filter(p => p.state === "open").length;
      const label = (h.hostname || h.ip) + "\\n[" + openCount + " open ports]";
      const nodeColor = gradeColors[h.risk_grade] || "#10b981";

      nodes.push({{
        id: hostId,
        label: label,
        shape: "box",
        margin: 10,
        color: {{
          background: "#151d30",
          border: nodeColor,
          highlight: {{
            background: "#1f2a44",
            border: "#00d2ff"
          }}
        }},
        borderWidth: 2,
        font: {{ color: "#ffffff", size: 12 }},
        hostData: h,
        hostIndex: idx
      }});

      edges.push({{
        from: "hub",
        to: hostId,
        color: {{ color: "rgba(0, 210, 255, 0.4)", highlight: "#00d2ff" }},
        smooth: {{ type: "continuous" }}
      }});

      // Connect open services as satellite nodes
      h.ports.filter(p => p.state === "open").forEach((p, pidx) => {{
        const portId = hostId + "_p_" + p.port;
        const portColor = p.risk_level === "Critical" ? "#ef4444" : (p.risk_level === "High" ? "#f97316" : "#38bdf8");
        nodes.push({{
          id: portId,
          label: p.port + "/" + p.service,
          shape: "dot",
          size: 9,
          color: {{ background: portColor, border: "#ffffff" }},
          font: {{ color: "#8899b5", size: 10 }}
        }});
        edges.push({{
          from: hostId,
          to: portId,
          color: {{ color: "rgba(255, 255, 255, 0.15)" }},
          length: 50
        }});
      }});
    }});

    const container = document.getElementById("topology");
    const networkData = {{
      nodes: new vis.DataSet(nodes),
      edges: new vis.DataSet(edges)
    }};

    const options = {{
      physics: {{
        barnesHut: {{
          gravitationalConstant: -3500,
          centralGravity: 0.3,
          springLength: 120,
          springConstant: 0.04
        }},
        stabilization: {{ iterations: 120 }}
      }},
      interaction: {{ hover: true, tooltipDelay: 200 }}
    }};

    const network = new vis.Network(container, networkData, options);

    // Sidebar & Details UI logic
    const hostListEl = document.getElementById("host-list");
    const detailsPanel = document.getElementById("details-panel");
    const detailsBody = document.getElementById("details-body");
    const backBtn = document.getElementById("back-btn");
    const searchInput = document.getElementById("host-search");

    function renderHostList(hosts) {{
      hostListEl.innerHTML = "";
      hosts.forEach((h, idx) => {{
        const openPorts = h.ports.filter(p => p.state === "open");
        const card = document.createElement("div");
        card.className = "host-card";
        card.dataset.index = idx;

        const portChips = openPorts.map(p => `<span class="port-chip">${{p.port}}/${{p.service}}</span>`).join("");

        card.innerHTML = `
          <div class="host-card-top">
            <div class="host-ip">${{h.ip}}</div>
            <span class="grade-badge grade-${{h.risk_grade}}">${{h.risk_grade}}</span>
          </div>
          <div class="host-vendor">${{h.vendor || (h.mac ? "MAC: " + h.mac : "Hardware: Generic")}}</div>
          <div class="host-os">${{h.hostname ? "Hostname: " + h.hostname + " • " : ""}}${{h.os_guess || "OS: Unknown"}}</div>
          <div style="margin-top: 6px;">${{portChips || '<span style="font-size:0.75rem; color:#64748b;">No open ports</span>'}}</div>
        `;

        card.addEventListener("click", () => showHostDetails(h, idx));
        hostListEl.appendChild(card);
      }});
    }}

    function showHostDetails(h, idx) {{
      hostListEl.style.display = "none";
      detailsPanel.style.display = "block";

      const openPorts = h.ports.filter(p => p.state === "open");
      let portsHtml = "";
      if (openPorts.length > 0) {{
        portsHtml = `
          <table class="port-table">
            <thead>
              <tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr>
            </thead>
            <tbody>
              ${{openPorts.map(p => `
                <tr>
                  <td><strong>${{p.port}}</strong>/tcp</td>
                  <td>${{p.service}}</td>
                  <td><span style="color:${{gradeColors[p.risk_level === 'Critical' ? 'F' : (p.risk_level === 'High' ? 'D' : 'A')] || '#fff'}}">${{p.risk_level}}</span></td>
                  <td>${{p.banner || '-'}}</td>
                </tr>
              `).join("")}}
            </tbody>
          </table>
        `;
      }} else {{
        portsHtml = `<p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">No open ports detected in the scanned range.</p>`;
      }}

      let issuesHtml = "";
      if (h.issues && h.issues.length > 0) {{
        issuesHtml = `<div style="margin-top:16px;">
          <h4 style="font-size:0.95rem; margin-bottom:8px; color:white;">Identified Vulnerabilities & Risks</h4>
          ${{h.issues.map(iss => `
            <div class="issue-item ${{iss.severity}}">
              <div class="issue-title">[${{iss.severity.toUpperCase()}}] ${{iss.title}} (Port ${{iss.port}})</div>
              <div class="issue-rec">${{iss.remediation}}</div>
            </div>
          `).join("")}}
        </div>`;
      }}

      detailsBody.innerHTML = `
        <div class="details-title">${{h.ip}}</div>
        <div class="details-meta">
          <strong>Hostname:</strong> <span>${{h.hostname || 'None'}}</span><br>
          <strong>MAC Address:</strong> <span>${{h.mac || 'N/A'}}</span><br>
          <strong>Hardware Vendor:</strong> <span>${{h.vendor || 'Unknown'}}</span><br>
          <strong>Inferred OS:</strong> <span>${{h.os_guess || 'Unknown'}}</span><br>
          <strong>Risk Score:</strong> <span>${{h.risk_score}}/100 (Grade ${{h.risk_grade}})</span>
        </div>
        <h4 style="font-size:0.95rem; margin-top:16px; color:white;">Open Ports & Services (${{openPorts.length}})</h4>
        ${{portsHtml}}
        ${{issuesHtml}}
      `;

      // Focus node in Vis.js
      network.focus("host_" + idx, {{
        scale: 1.2,
        animation: {{ duration: 600, easingFunction: "easeInOutQuad" }}
      }});
    }}

    backBtn.addEventListener("click", () => {{
      detailsPanel.style.display = "none";
      hostListEl.style.display = "block";
    }});

    // Click on Vis.js node opens details
    network.on("click", function(params) {{
      if (params.nodes.length > 0) {{
        const nodeId = params.nodes[0];
        if (nodeId.startsWith("host_") && !nodeId.includes("_p_")) {{
          const idx = parseInt(nodeId.replace("host_", ""));
          showHostDetails(scanData.hosts[idx], idx);
        }}
      }}
    }});

    // Filter hosts search
    searchInput.addEventListener("input", (e) => {{
      const query = e.target.value.toLowerCase().trim();
      if (!query) {{
        renderHostList(scanData.hosts);
        return;
      }}
      const filtered = scanData.hosts.filter(h => {{
        const portsStr = h.ports.map(p => p.port + " " + p.service).join(" ").toLowerCase();
        return (
          h.ip.toLowerCase().includes(query) ||
          (h.hostname && h.hostname.toLowerCase().includes(query)) ||
          (h.vendor && h.vendor.toLowerCase().includes(query)) ||
          portsStr.includes(query)
        );
      }});
      renderHostList(filtered);
    }});

    renderHostList(scanData.hosts);
  </script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return str(path.resolve())
