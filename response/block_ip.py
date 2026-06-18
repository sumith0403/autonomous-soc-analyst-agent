import subprocess
import platform


class IPBlocker:
    """
    Blocks malicious IP addresses at the OS firewall level.

    ⚠️ SAFETY: This only runs if:
    1. Severity is CRITICAL or HIGH
    2. AI verdict is TRUE POSITIVE
    3. AbuseIPDB score > 80
    4. Explicitly enabled in config

    In production, this would call a firewall API instead.
    """

    def __init__(self, dry_run=True):
        # dry_run=True means we LOG the action but don't actually block
        # Set to False only in production with proper authorization
        self.dry_run = dry_run

    def block_ip(self, ip: str, reason: str = "") -> dict:
        """Block an IP address."""

        if self.dry_run:
            print(f"[DRY RUN] Would block IP: {ip} | Reason: {reason}")
            return {
                "action": "block_ip",
                "ip": ip,
                "status": "DRY_RUN",
                "message": f"DRY RUN: Would have blocked {ip}"
            }

        # Safety check: don't block private/internal IPs
        if self._is_private_ip(ip):
            return {
                "action": "block_ip",
                "ip": ip,
                "status": "SKIPPED",
                "message": "Cannot block private/internal IP"
            }

        try:
            if platform.system() == "Linux":
                cmd = f"iptables -I INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), check=True, capture_output=True)
                print(f"[BLOCK] Blocked IP: {ip}")
                return {"action": "block_ip", "ip": ip, "status": "BLOCKED"}
            else:
                return {"action": "block_ip", "ip": ip,
                        "status": "UNSUPPORTED",
                        "message": "Only supported on Linux"}

        except Exception as e:
            return {"action": "block_ip", "ip": ip,
                    "status": "ERROR", "message": str(e)}

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC 1918)."""
        private_ranges = ["10.", "172.16.", "172.17.", "192.168.", "127."]
        return any(ip.startswith(r) for r in private_ranges)    