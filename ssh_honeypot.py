import os
import socket
import time
import random
import threading
from datetime import datetime

# ===================== LOG FUNCTIONS =====================
if not os.path.exists("logs"):
    os.makedirs("logs")

LOG_FILE = "logs/events.log"
def log_event(filename, text):
    filepath = os.path.join("logs", filename)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp()}] {text}\n")

def log_error(text):
    filepath = os.path.join("logs", "error.log")
    with open(filepath, "a") as f:
        f.write(f"[{timestamp()}] ERROR: {text}\n")

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ===================== BRUTE FORCE SIMULATION =====================

def brute_Force_attack():
    passwords = ["1566", "44545", "454632", "656643", "45602", "admin1234"]
    passwd = random.choice(passwords) + str(random.randint(0, 99))
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))

    log_text = f"[{timestamp()}] Bruteforce attempt from {ip} using password {passwd}"
    log_event("brute.log", log_text)
    print(log_text)

def run_bruteForce():
    while True:
        brute_Force_attack()
        time.sleep(random.randint(1, 5))

# ===================== PORT SCAN SIMULATION =====================

def port_scan_attack():
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    port = random.choice([21, 22, 23, 24, 25, 26])
    status = random.choice(["open", "close"])

    log_text = f"[{timestamp()}] Port Scan from {ip} -> Port {port} Status={status}"
    log_event("port.log", log_text)
    print(log_text)

def run_portscan():
    while True:
        port_scan_attack()
        time.sleep(random.randint(2, 6))

# ====================== SQL INJECTION =======================
def sql_injection_attack():
    """محاكاة هجمات SQL Injection"""
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users",
        "UNION SELECT username, password FROM users"
    ]
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # تم تصحيح الدالة generate_realistic_ip
    payload = random.choice(payloads)
    
    log_event("sqli.log", f"[{timestamp()}] SQLi from {ip}: {payload}")
    print(f"💉 SQL Injection: {ip}")

def run_sql_injection():
    while True:
        sql_injection_attack()
        time.sleep(random.randint(3, 8))

#================== CREDENTIAL STUFFING ATTACK ==============

def credential_stuffing_attack():
    users = ["Hadeel", "Fajr", "Nada", "Majd"]
    password = "admin123"
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    
    for user in users:
        log_text = f"[{timestamp()}] Credential Stuffing from {ip} {user}:{password}"
        log_event("credential.log", log_text)

    print(f"[{timestamp()}] Credential Stuffing attack from {ip}")  # تم التصحيح
    time.sleep(0.5)

def run_credential_stuffing():
    while True:
        credential_stuffing_attack()
        time.sleep(random.randint(5, 10))

# ===================== FAKE SHELL =====================

def fake_shell(client, ip):
    file_contents = {
        "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
user:x:1000:1000:User,,,:/home/user:/bin/bash""",
        "/root/flag.txt": "CTF{H4rd3n_Y0ur_5h3ll}",
        "/root/notes.txt": "Important notes here...",
        "/var/backups/db.sql": "CREATE TABLE users (id INT, name VARCHAR(255));",
        "/var/backups/old.tar.gz": "Archive content would be here"
    }
    
    fake_filesystem = {
        "/root": ["flag.txt", "notes.txt"],
        "/var/backups": ["db.sql", "old.tar.gz"],
        "/etc": ["passwd", "shadow", "hosts"]
    }
    
    current_path = "/root"
    
    client.send(b"\nWelcome to Ubuntu 20.04 LTS\n")
    client.send(b"root@server:~# ")
    log_event("sessions.log", f"[{timestamp()}] {ip} -> Session started")

    while True:
        try:
            cmd = client.recv(1024).decode().strip()
        except Exception as e:
            log_error(str(e))
            break

        if not cmd:
            client.send(b"root@server:~# ")
            continue

        log_event("commands.log", f"[{timestamp()}] {ip} -> CMD: {cmd}")

        if cmd == "exit":
            client.send(b"logout\n")
            log_event("sessions.log", f"[{timestamp()}] {ip} -> Session ended")
            break

        elif cmd == "pwd":
            client.send(current_path.encode() + b"\nroot@server:~# ")

        elif cmd == "whoami":
            client.send(b"root\nroot@server:~# ")

        elif cmd == "ls":
            if current_path in fake_filesystem:
                out = "\n".join(fake_filesystem[current_path]) + "\n"
                client.send(out.encode() + b"root@server:~# ")
            else:
                client.send(b"\nroot@server:~# ")

        elif cmd.startswith("cat"):
            parts = cmd.split()
            if len(parts) == 2:
                path = parts[1] if parts[1].startswith("/") else current_path + "/" + parts[1]
                if path in file_contents:
                    client.send(file_contents[path].encode() + b"\nroot@server:~# ")
                else:
                    client.send(b"cat: No such file\nroot@server:~# ")
            else:
                client.send(b"Usage: cat <file>\nroot@server:~# ")

        elif cmd == "uname -a":
            client.send(b"Linux server 5.4.0-42-generic x86_64 GNU/Linux\nroot@server:~# ")

        elif cmd == "ip a":
            client.send(b"1: lo\n2: eth0\nroot@server:~# ")

        elif cmd == "history":
            client.send(b"1 ls\n2 cd /etc\n3 cat passwd\nroot@server:~# ")

        elif cmd == "ps":
            client.send(b"PID CMD\n1 systemd\n234 sshd\nroot@server:~# ")

        elif cmd == "ps aux":
            client.send(b"root 234 sshd\nmysql 410 mysqld\nroot@server:~# ")

        elif cmd in ["netstat -tulnp", "netstat -tlnp", "netstat -an", "netstat -na"]:
            output = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd           
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      8910/mysqld         
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      9012/apache2        
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      9012/apache2        
tcp6       0      0 :::22                   :::*                    LISTEN      1234/sshd          
tcp6       0      0 :::80                   :::*                    LISTEN      9012/apache2        
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                  
udp        0      0 0.0.0.0:123             0.0.0.0:*                           -                  
udp6       0      0 :::123                  :::*                                -                  \n"""
            client.send(output.encode() + b"root@server:~# ")

        elif cmd in ["ss -tuln", "ss -tulnp", "ss -tlnp"]:
            client.send(b"tcp LISTEN 0.0.0.0:22\nroot@server:~# ")

        elif cmd == "sudo -l":
            client.send(b"Matching Defaults entries for root on server:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\nUser root may run the following commands on server:\n    (ALL : ALL) ALL\nroot@server:~# ")

        elif cmd == "ls /root":
            client.send(b"flag.txt\nnotes.txt\nroot@server:~# ")

        elif cmd == "ls /var/backups":
            client.send(b"db.sql\nold.tar.gz\nroot@server:~# ")

        elif cmd == "cat /etc/shadow":
            client.send(b"Permission denied\nroot@server:~# ")

        elif cmd.startswith("wget") or cmd.startswith("curl"):
            log_event("downloads.log", f"[{timestamp()}] {ip} -> {cmd}")
            client.send(b"Network unreachable\nroot@server:~# ")

        elif cmd.startswith("rm"):
            log_event("danger.log", f"[{timestamp()}] {ip} -> {cmd}")
            client.send(b"Read-only filesystem\nroot@server:~# ")

        elif cmd == "free -m":
            client.send(b"              total        used        free      shared  buff/cache   available\nMem:           7985        3124        2456         123        2404        4401\nSwap:          2047           0        2047\nroot@server:~# ")

        elif cmd == "who":
            client.send(b"root pts/0\nroot@server:~# ")

        elif cmd.startswith("echo"):
            msg = cmd.replace("echo", "").strip()
            client.send(msg.encode() + b"\nroot@server:~# ")

        elif cmd in ["df -h", "df", "df -i"]:
            if "-i" in cmd:
                output = """Filesystem       Inodes  IUsed    IFree IUse% Mounted on
udev             1000000    401   999599    1% /dev
/dev/sda1       26214400 145632 26068768    1% /
tmpfs            1000000     12   999988    1% /run
"""
            else:
                output = """Filesystem      Size  Used Avail Use% Mounted on
udev            3.9G     0  3.9G   0% /dev
tmpfs           796M  1.2M  795M   1% /run
/dev/sda1        40G   18G   20G  47% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda15      105M  5.2M  100M   5% /boot/efi
tmpfs           796M     0  796M   0% /run/user/0
"""
            client.send(output.encode() + b"root@server:~# ")

        elif cmd.startswith("service"):
            client.send(b"service: command not found\nroot@server:~# ")

        elif cmd.startswith("clear"):
            client.send(b"\n" * 50)
            client.send(b"root@server:~# ")

        elif cmd == "uptime":
            up_time = random.choice([
                "10:21:33 up 2 days, 3 users, load average: 0.12, 0.08, 0.03",
                "18:05:11 up 7 hours, 1 user, load average: 0.55, 0.40, 0.20",
                "03:44:59 up 12 days, 5 users, load average: 0.02, 0.01, 0.00"
            ])
            client.send(up_time.encode() + b"\nroot@server:~# ")

        elif cmd == "env":
            env_vars = {
                "USER": "root",
                "HOME": "/root",
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "en_US.UTF-8"
            }
            out = "\n".join(f"{k}={v}" for k, v in env_vars.items())
            client.send(out.encode() + b"\nroot@server:~# ")

        elif cmd.startswith("nmap ") or cmd.startswith("nc ") or cmd.startswith("netcat "):
            log_event("scan_attempts.log", f"[{timestamp()}] {ip} attempted network scan: {cmd}")
            client.send(b"Command not available on this system\nroot@server:~# ")

        elif cmd.startswith("telnet "):
            host_port = cmd[7:].strip()
            client.send(f"Trying {host_port}...\n".encode())
            time.sleep(1)
            client.send(b"telnet: Unable to connect to remote host: Connection refused\nroot@server:~# ")

        elif cmd == "last":
            output = f"""root     pts/0        {ip}             Tue Dec 26 10:35   still logged in
root     pts/0        192.168.1.50     Mon Dec 25 14:20 - 17:30  (03:10)
root     pts/0        192.168.1.50     Mon Dec 25 09:15 - 12:30  (03:15)
reboot   system boot  5.15.0-58-generic Mon Dec 25 09:10 - 10:45 (1+01:35)

wtmp begins Mon Dec 25 09:10:26 2023
"""
            client.send(output.encode() + b"root@server:~# ")

        elif cmd == "lastlog":
            output = """Username         Port     From             Latest
root             pts/0    192.168.1.50     Tue Dec 26 10:35:35 +0000 2023
daemon                                     **Never logged in**
bin                                        **Never logged in**
sys                                        **Never logged in**
"""
            client.send(output.encode() + b"root@server:~# ")

        else:
            client.send(b"bash: command not found\nroot@server:~# ")

# ===================== START THREADS =========================

threading.Thread(target=run_bruteForce, daemon=True).start()
threading.Thread(target=run_portscan, daemon=True).start()
threading.Thread(target=run_sql_injection, daemon=True).start()
threading.Thread(target=run_credential_stuffing, daemon=True).start()

print("Attack simulation running... (will not stop)")

# ===================== SERVER =====================

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 2223))
server.listen(5)

print("Listening on port 2223...")

while True:
    client, addr = server.accept()
    ip = addr[0]

    log_event("connections.log", f"[{timestamp()}] New connection from {ip}")

    attempts = 0
    while attempts < 3:
        client.send(b"login: ")
        try:
            user = client.recv(1024).decode().strip()
        except:
            break
        client.send(b"password: ")
        try:
            pwd = client.recv(1024).decode().strip()
        except:
            break

        log_event("credentials.log", f"[{timestamp()}] {ip} -> {user}:{pwd}")
        attempts += 1
        client.send(b"Access Denied\n")

    client.send(b"Too many failed attempts\n")
    fake_shell(client, ip)
    client.close()