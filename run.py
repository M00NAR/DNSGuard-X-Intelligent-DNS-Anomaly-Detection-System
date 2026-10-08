"""Click-to-run launcher for DNSGuard-X.

VS Code's "Run Python File" button executes a file directly, which breaks the
package-relative imports in dnsguard/main.py. This script fixes that: it puts the
project root on the path and calls the CLI as a proper package.

Just press Run (no arguments) to analyse data/pcaps/mixed.pcap. You can still pass
the usual CLI flags on the command line, e.g.:

    python run.py --pcap data/pcaps/dga.pcap
    python run.py --live --iface "Ethernet"
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dnsguard.main import main

if __name__ == "__main__":
    # If no arguments were given (e.g. the Run button), default to the demo capture.
    if len(sys.argv) == 1:
        default_pcap = ROOT / "data" / "pcaps" / "mixed.pcap"
        if not default_pcap.is_file():
            print("No PCAP found. Generating test traffic first...\n")
            from tools import generate_traffic
            generate_traffic.main()
            print()
        sys.argv += ["--pcap", str(default_pcap)]
    raise SystemExit(main())
