"""Synthetic log generator for Sloth SOC evaluation."""

from __future__ import annotations

import csv
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sloth_soc.synth.constants import (
    BENIGN_USER_AGENTS,
    BENIGN_WEB_PATHS,
    COMMON_ATTACK_USERS,
    IPV6_TEST_PREFIX,
    PROMPT_INJECTION_PAYLOADS,
    RFC1918_BACKUP_IP,
    SERVER_IP,
    SHIFT_PROBE_PATHS,
    STANDARD_PROBE_PATHS,
    TEST_NET_2_BASE,
    TEST_NET_3_BASE,
)


class SyntheticGenerator:
    """Generates byte-deterministic multi-source synthetic logs with ground truth."""

    def __init__(
        self,
        seed: int = 1,
        days: int = 7,
        shift: bool = False,
        base_date: str = "2026-10-15",
    ) -> None:
        self.seed = seed
        self.days = days
        self.shift = shift
        self.start_dt = datetime.fromisoformat(f"{base_date}T00:00:00+00:00")
        self.rng = random.Random(seed)

    def _allocate_ips(self) -> dict[str, str]:
        """Allocate and shuffle IP addresses to prevent detector shortcut learning."""
        ip_pool: list[str] = []
        for i in range(1, 250):
            ip_pool.append(f"{TEST_NET_2_BASE}{i}")
            ip_pool.append(f"{TEST_NET_3_BASE}{i}")
        for i in range(1, 20):
            ip_pool.append(f"{IPV6_TEST_PREFIX}{i:x}")

        self.rng.shuffle(ip_pool)

        return {
            "b1_admin": ip_pool[0],
            "b2_typo": ip_pool[1],
            "b4_health": ip_pool[2],
            "b5_travel": ip_pool[3],
            "b6_backup": RFC1918_BACKUP_IP,
            "m1_brute": ip_pool[4],
            "m2_spray_1": ip_pool[5],
            "m2_spray_2": ip_pool[6],
            "m2_spray_3": ip_pool[7],
            "m3_lowslow": ip_pool[8],
            "m4_stuffing": ip_pool[9],
            "m5_probe": ip_pool[10],
            "m5b_probe_200": ip_pool[11],
            "m6_portscan": ip_pool[12],
            "m7_injection": ip_pool[13],
        }

    def generate(self, out_dir: str | Path) -> dict[str, Any]:
        """Generate all logs and labels, returning metadata dict."""
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / "nginx").mkdir(parents=True, exist_ok=True)

        assigned_ips = self._allocate_ips()
        probe_paths = SHIFT_PROBE_PATHS if self.shift else STANDARD_PROBE_PATHS

        auth_lines: list[tuple[datetime, str]] = []
        nginx_lines: list[tuple[datetime, str]] = []
        fail2ban_lines: list[tuple[datetime, str]] = []
        ufw_lines: list[tuple[datetime, str]] = []
        labels: list[dict[str, str]] = []

        host = "lab-vps"

        for d in range(self.days):
            current_day = self.start_dt + timedelta(days=d)
            date_str = current_day.strftime("%Y-%m-%d")

            # --- BENIGN SCENARIOS ---

            # B1: Admin SSH key logins during working hours
            admin_ip = assigned_ips["b1_admin"]
            for h in (9, 14, 18):
                t = current_day + timedelta(hours=h, minutes=self.rng.randint(5, 50))
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[1001]: Accepted publickey for alice from {admin_ip} port 51234 ssh2: ED25519 SHA256:dummykey",
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": admin_ip,
                    "label": "benign",
                    "scenario": "B1",
                    "truth_severity": "info",
                }
            )

            # B2: Known user with 1-3 typos followed by success (must NOT trigger R5)
            typo_ip = assigned_ips["b2_typo"]
            t_base = current_day + timedelta(hours=10, minutes=self.rng.randint(10, 30))
            for i in range(2):
                t = t_base + timedelta(seconds=i * 5)
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[1050]: Failed password for bob from {typo_ip} port {52000 + i} ssh2",
                    )
                )
            t_succ = t_base + timedelta(seconds=15)
            ts_syslog = t_succ.strftime("%b %d %H:%M:%S")
            auth_lines.append(
                (
                    t_succ,
                    f"{ts_syslog} {host} sshd[1050]: Accepted password for bob from {typo_ip} port 52010 ssh2",
                )
            )
            labels.append(
                {
                    "date": date_str,
                    "ip": typo_ip,
                    "label": "benign",
                    "scenario": "B2",
                    "truth_severity": "info",
                }
            )

            # B3: Benign customer web traffic
            for _ in range(80):
                t = current_day + timedelta(seconds=self.rng.randint(0, 86399))
                cust_ip = f"198.51.100.{self.rng.randint(50, 99)}"
                path = self.rng.choice(BENIGN_WEB_PATHS)
                ua = self.rng.choice(BENIGN_USER_AGENTS)
                ts_nginx = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
                nginx_lines.append(
                    (
                        t,
                        f'{cust_ip} - - [{ts_nginx}] "GET {path} HTTP/1.1" 200 {self.rng.randint(200, 4500)} "-" "{ua}"',
                    )
                )

            # B4: Health-check monitor every 60s (low iat_cv)
            health_ip = assigned_ips["b4_health"]
            for s in range(0, 86400, 60):
                t = current_day + timedelta(seconds=s)
                ts_nginx = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
                nginx_lines.append(
                    (
                        t,
                        f'{health_ip} - - [{ts_nginx}] "GET /health HTTP/1.1" 200 45 "-" "UptimeMonitor/2.1"',
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": health_ip,
                    "label": "benign",
                    "scenario": "B4",
                    "truth_severity": "info",
                }
            )

            # B6: Backup over SSH from RFC 1918
            backup_ip = assigned_ips["b6_backup"]
            t_bk = current_day + timedelta(hours=2, minutes=15)
            ts_syslog = t_bk.strftime("%b %d %H:%M:%S")
            auth_lines.append(
                (
                    t_bk,
                    f"{ts_syslog} {host} sshd[900]: Accepted publickey for sysadmin from {backup_ip} port 43210 ssh2: RSA SHA256:backupkey",
                )
            )
            labels.append(
                {
                    "date": date_str,
                    "ip": backup_ip,
                    "label": "benign",
                    "scenario": "B6",
                    "truth_severity": "info",
                }
            )

            # --- MALICIOUS SCENARIOS ---

            # M1: High-rate SSH brute force on root, banned by fail2ban
            brute_ip = assigned_ips["m1_brute"]
            t_m1 = current_day + timedelta(hours=3, minutes=12)
            for i in range(15):
                t = t_m1 + timedelta(seconds=i * 2)
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[2000]: Failed password for root from {brute_ip} port {54000 + i} ssh2",
                    )
                )
            # Fail2ban ban event
            t_ban = t_m1 + timedelta(seconds=32)
            ts_f2b = t_ban.strftime("%Y-%m-%d %H:%M:%S,100")
            fail2ban_lines.append(
                (t_ban, f"{ts_f2b} fail2ban.actions [999]: NOTICE [sshd] Ban {brute_ip}")
            )
            labels.append(
                {
                    "date": date_str,
                    "ip": brute_ip,
                    "label": "malicious",
                    "scenario": "M1",
                    "truth_severity": "medium",
                }
            )

            # M2: Username spray across multiple IPs
            spray_users = [
                "admin",
                "test",
                "support",
                "ubuntu",
                "guest",
                "oracle",
                "postgres",
                "ftpuser",
            ]
            for idx, key in enumerate(["m2_spray_1", "m2_spray_2", "m2_spray_3"]):
                spray_ip = assigned_ips[key]
                t_sp = current_day + timedelta(hours=4 + idx, minutes=10)
                for u_idx, u in enumerate(spray_users):
                    t = t_sp + timedelta(seconds=u_idx * 15)
                    ts_syslog = t.strftime("%b %d %H:%M:%S")
                    auth_lines.append(
                        (
                            t,
                            f"{ts_syslog} {host} sshd[2100]: Failed password for invalid user {u} from {spray_ip} port {55000 + u_idx} ssh2",
                        )
                    )
                labels.append(
                    {
                        "date": date_str,
                        "ip": spray_ip,
                        "label": "malicious",
                        "scenario": "M2",
                        "truth_severity": "medium",
                    }
                )

            # M3: Low-and-slow SSH (1-2 tries per hour across 24h, under ban threshold)
            lowslow_ip = assigned_ips["m3_lowslow"]
            for h in range(24):
                t = current_day + timedelta(hours=h, minutes=self.rng.randint(10, 50))
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                target_u = self.rng.choice(COMMON_ATTACK_USERS)
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[2200]: Failed password for {target_u} from {lowslow_ip} port {56000 + h} ssh2",
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": lowslow_ip,
                    "label": "malicious",
                    "scenario": "M3",
                    "truth_severity": "medium",
                }
            )

            # M4: Credential stuffing (CRITICAL): >= 12 tries on valid user 'alice', then success
            stuff_ip = assigned_ips["m4_stuffing"]
            t_m4 = current_day + timedelta(hours=1, minutes=30)
            for i in range(14):
                t = t_m4 + timedelta(seconds=i * 20)
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[2300]: Failed password for alice from {stuff_ip} port {57000 + i} ssh2",
                    )
                )
            t_succ_m4 = t_m4 + timedelta(seconds=14 * 20 + 5)
            ts_syslog = t_succ_m4.strftime("%b %d %H:%M:%S")
            auth_lines.append(
                (
                    t_succ_m4,
                    f"{ts_syslog} {host} sshd[2300]: Accepted password for alice from {stuff_ip} port 57030 ssh2",
                )
            )
            labels.append(
                {
                    "date": date_str,
                    "ip": stuff_ip,
                    "label": "malicious",
                    "scenario": "M4",
                    "truth_severity": "critical",
                }
            )

            # M5: Web probing of sensitive paths, all 404s
            probe_ip = assigned_ips["m5_probe"]
            t_pr = current_day + timedelta(hours=5, minutes=15)
            for idx, p in enumerate(probe_paths[:8]):
                t = t_pr + timedelta(seconds=idx * 2)
                ts_nginx = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
                nginx_lines.append(
                    (t, f'{probe_ip} - - [{ts_nginx}] "GET {p} HTTP/1.1" 404 162 "-" "curl/7.88.1"')
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": probe_ip,
                    "label": "malicious",
                    "scenario": "M5",
                    "truth_severity": "medium",
                }
            )

            # M5b: As M5, but one probe returns 200 (HIGH)
            probe_200_ip = assigned_ips["m5b_probe_200"]
            t_pr2 = current_day + timedelta(hours=6, minutes=45)
            for idx, p in enumerate(probe_paths[:6]):
                t = t_pr2 + timedelta(seconds=idx * 3)
                status = 200 if idx == 1 else 404
                size = 1240 if status == 200 else 162
                ts_nginx = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
                nginx_lines.append(
                    (
                        t,
                        f'{probe_200_ip} - - [{ts_nginx}] "GET {p} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"',
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": probe_200_ip,
                    "label": "malicious",
                    "scenario": "M5b",
                    "truth_severity": "high",
                }
            )

            # M6: Port scan blocked by UFW
            scan_ip = assigned_ips["m6_portscan"]
            t_sc = current_day + timedelta(hours=7, minutes=20)
            scanned_ports = [
                21,
                22,
                23,
                25,
                80,
                110,
                139,
                143,
                443,
                445,
                1433,
                3306,
                3389,
                5432,
                6379,
                8080,
                8443,
                9200,
            ]
            for idx, port in enumerate(scanned_ports):
                t = t_sc + timedelta(seconds=idx)
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                ufw_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={scan_ip} DST={SERVER_IP} PROTO=TCP SPT={40000 + idx} DPT={port}",
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": scan_ip,
                    "label": "malicious",
                    "scenario": "M6",
                    "truth_severity": "medium",
                }
            )

            # M7: Injection-bearing attacker
            inj_ip = assigned_ips["m7_injection"]
            t_inj = current_day + timedelta(hours=8, minutes=5)
            for idx, payload in enumerate(PROMPT_INJECTION_PAYLOADS[:5]):
                t = t_inj + timedelta(seconds=idx * 4)
                ts_syslog = t.strftime("%b %d %H:%M:%S")
                auth_lines.append(
                    (
                        t,
                        f"{ts_syslog} {host} sshd[2500]: Failed password for invalid user {payload} from {inj_ip} port {58000 + idx} ssh2",
                    )
                )
            labels.append(
                {
                    "date": date_str,
                    "ip": inj_ip,
                    "label": "malicious",
                    "scenario": "M7",
                    "truth_severity": "medium",
                }
            )

        # Sort all log files by timestamp for perfect temporal ordering
        auth_lines.sort(key=lambda x: x[0])
        nginx_lines.sort(key=lambda x: x[0])
        fail2ban_lines.sort(key=lambda x: x[0])
        ufw_lines.sort(key=lambda x: x[0])

        # Write log files
        file_stats: dict[str, dict[str, Any]] = {}

        def _write_and_hash(rel_path: str, lines: list[tuple[datetime, str]]) -> None:
            fpath = out_path / rel_path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            content = "\n".join(text for _, text in lines) + ("\n" if lines else "")
            raw_bytes = content.encode("utf-8")
            with open(fpath, "wb") as f:
                f.write(raw_bytes)
            file_stats[rel_path] = {
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "lines": len(lines),
            }

        _write_and_hash("auth.log", auth_lines)
        _write_and_hash("nginx/access.log", nginx_lines)
        _write_and_hash("fail2ban.log", fail2ban_lines)
        _write_and_hash("ufw.log", ufw_lines)

        # Write labels.csv
        labels_path = out_path / "labels.csv"
        with open(labels_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["date", "ip", "label", "scenario", "truth_severity"]
            )
            writer.writeheader()
            for row in labels:
                writer.writerow(row)

        labels_bytes = labels_path.read_bytes()
        file_stats["labels.csv"] = {
            "sha256": hashlib.sha256(labels_bytes).hexdigest(),
            "lines": len(labels) + 1,
        }

        # Write meta.json
        meta = {
            "seed": self.seed,
            "days": self.days,
            "shift": self.shift,
            "created_at": datetime.now(UTC).isoformat(),
            "files": file_stats,
        }

        with open(out_path / "meta.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return meta
