from django.http import HttpResponse
import textwrap

from .api_logs_parser import run_log_parser_once
from . import config

def view_firewall_logs(request):
    ip_filter = request.GET.get("ip")
    logs = run_log_parser_once(ip_filter)

    # Start building HTML output
    output = textwrap.dedent("""\
    <h2>Firewall Logs</h2>

    <label for="refreshRate">Auto-Refresh: </label>
    <select id="refreshRate" onchange="setRefreshRate()">
      <option value="0">Off</option>
      <option value="5000">Every 5s</option>
      <option value="10000">Every 10s</option>
      <option value="30000">Every 30s</option>
    </select>

    <script>
    let refreshTimeout = null;

    function setRefreshRate() {
        const rate = parseInt(document.getElementById('refreshRate').value);
        localStorage.setItem("refreshRate", rate);
        if (refreshTimeout) clearTimeout(refreshTimeout);
        if (rate > 0) {
            refreshTimeout = setTimeout(() => {
                window.location.reload();
            }, rate);
        }
    }

    window.onload = function() {
        const savedRate = localStorage.getItem("refreshRate") || "5000";
        document.getElementById('refreshRate').value = savedRate;
        if (parseInt(savedRate) > 0) {
            setRefreshRate();
        }
    };
    </script>

        <pre>
""")


    output += "\n".join(logs)
    output += "</pre>"

    output += "<h2>Enriched IP Info</h2><pre>"
    for ip, data in config.IP_TABLE.items():
        output += (
            f"🌐 {ip} - {data.get('dns_name', 'N/A')} - "
            f"{data.get('isp', 'N/A')} - {data.get('city', 'N/A')}, {data.get('country', 'N/A')}\n"
        )
    output += "</pre>"

    return HttpResponse(output)
