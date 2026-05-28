# THEIA E3 Data — Schema & Examples

What the detection model actually eats, end to end, with **real records pulled from
`ta1-theia-e3-official-6r.json.8`** (the held-out test split). Read this first.

> TL;DR pipeline of the data:
> **raw CDM18 JSON** → two-pass parse → **6-column edge rows** → attribute merge
> (adds cmdLine/path) → per-node **token document `[exec, action, path]`** →
> Word2Vec → **30-dim node vector** → GraphSAGE/LGBM scores the node *in its graph*.

---

## 1. Source

- **Dataset:** DARPA Transparent Computing, Engagement 3, **THEIA** team.
- **Host:** single Linux desktop. `source": "SOURCE_LINUX_THEIA"`, `CDMVersion": "18"`,
  hostId `0A00063C-5254-00F0-0D60-000000000070`, IP `10.0.6.60`, iface `eth0`.
- **Format:** CDM18 (Common Data Model v18), one JSON object per line. Each line wraps a
  `datum` of exactly one record type under key
  `com.bbn.tc.schema.avro.cdm18.<Type>`.
- **Splits on disk** (gitignored, `external/Flash-IDS/`):
  - `ta1-theia-e3-official-1r.json[.1-9]` — **train** period (benign-dominant).
  - `ta1-theia-e3-official-6r.json[.1-12]` — **test** period; split `.8` is the graph
    used for the headline eval.
- **Scale:** test split `.8` alone parses to **9,426,832 edges**.

---

## 2. Raw record types (real examples)

The parser cares about 5 of these. All examples are verbatim from the test split.

### 2.1 `Subject` — a process (the only thing that acts)

```json
{
 "uuid": "901C6796-0200-0000-0000-000000000020",
 "type": "SUBJECT_PROCESS",
 "cid": 7312,
 "parentSubject": {"com.bbn.tc.schema.avro.cdm18.UUID": "D1050F00-..."},
 "localPrincipal": "74000000-0000-0000-0000-000000000060",
 "startTimestampNanos": 1523543728782019042,
 "cmdLine": {"string": "/usr/lib/postgresql/9.1/bin/postgres -D /var/lib/postgresql/9.1/main -c config_file=/etc/postgresql/9.1/main/postgresql.conf"},
 "properties": {"map": {"tgid": "7312", "path": "/usr/lib/postgresql/9.1/bin/postgres", "ppid": "1489"}}
}
```

Carries the **`cmdLine`** and **`properties.map.path`** — the richest signal in the
whole dataset (see §5).

### 2.2 `FileObject` — a file

```json
{
 "uuid": "0100D00F-A64B-1E00-0000-00006512C22D",
 "type": "FILE_OBJECT_BLOCK",
 "baseObject": {"properties": {"map": {
    "dev": "265289729", "inode": "1985446",
    "filename": "/var/lib/postgresql/9.1/main/pg_stat_tmp/pgstat.tmp"}}},
 "localPrincipal": {"com.bbn.tc.schema.avro.cdm18.UUID": "74000000-...-060"}
}
```

### 2.3 `NetFlowObject` — a socket / connection

```json
{
 "uuid": "80370C6E-7ABF-8037-0C0A-350000000040",
 "localAddress": "128.55.12.110", "localPort": 49018,
 "remoteAddress": "128.55.12.10", "remotePort": 53
}
```

### 2.4 `MemoryObject` — a mapped memory region

```json
{"uuid": "241C00B0-...-050", "memoryAddress": 4529895813120, "size": {"long": 4096}}
```

### 2.5 `Event` — the edge (verb connecting subject → object)

```json
{
 "uuid": "E96DD14D-F1B6-2415-93DB-3A0200000010",
 "type": "EVENT_MPROTECT",
 "subject":         {"com.bbn.tc.schema.avro.cdm18.UUID": "241C1896-...-020"},
 "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": "241C0090-...-050"},
 "predicateObjectPath": null,
 "predicateObject2": {"com.bbn.tc.schema.avro.cdm18.UUID": "00000000-0000-..."},
 "timestampNanos": 1523543721467014633,
 "properties": {"map": {"prot": "PROT_READ|PROT_EXEC"}}
}
```

- `subject` = actor UUID (always a process).
- `predicateObject` (+ optional `predicateObject2`) = target UUID(s).
- `type` = the action. **One Event can yield two edges** (object + object2).

### 2.6 `Principal` / `Host` — context (parser ignores)

```json
"Principal": {"uuid": "21000000-...-060", "type": "PRINCIPAL_LOCAL", "userId": "33", "groupIds": ["33","33","33","33"]}
"Host": {"uuid": "0A00063C-...-070", "hostType": "HOST_DESKTOP", "interfaces": [{"name": "eth0", "ipAddresses": ["10.0.6.60"]}]}
```

---

## 3. Action vocabulary (`EVENT_*`)

17 action types in the test split. Distribution (col 5 of parsed edges):

| count | action | | count | action |
|--:|---|---|--:|---|
| 4,668,430 | EVENT_MPROTECT | | 61,154 | EVENT_SENDTO |
| 1,820,642 | EVENT_RECVFROM | | 35,224 | EVENT_UNLINK |
| 770,138 | EVENT_READ | | 26,036 | EVENT_WRITE_SOCKET_PARAMS |
| 625,376 | EVENT_OPEN | | 25,200 | EVENT_CLONE |
| 520,430 | EVENT_MMAP | | 20,562 | EVENT_READ_SOCKET_PARAMS |
| 305,792 | EVENT_WRITE | | 11,290 | EVENT_EXECUTE |
| 195,920 | EVENT_RECVMSG | | 1,220 | EVENT_SHM |
| 181,158 | EVENT_CONNECT | | 518 | EVENT_MODIFY_FILE_ATTRIBUTES |
| 157,742 | EVENT_SENDMSG | | | |

> Heavily skewed: MPROTECT + RECVFROM = 69% of edges. Memory/network noise dominates;
> the rare verbs (EXECUTE, CLONE, UNLINK) carry most causal meaning.

---

## 4. Parsed representation — the 6-column edge

`theia_flash_common.parse_split()` does a **two-pass, memory-bounded** scan:

- **Pass A** — read split, collect every UUID referenced as subject/object by an Event.
- **Pass B** — scan all splits, resolve **node type** only for those UUIDs.
- **write_edges** — emit one tab-separated row per (subject→object) Event edge:

```
actorID                               actor_type       objectID                              object          action          timestamp
241C1896-0200-0000-0000-000000000020  SUBJECT_PROCESS  241C0090-D4B2-1E04-0000-000000000050  MemoryObject    EVENT_MPROTECT  1523543721467014633
241C1896-0200-0000-0000-000000000020  SUBJECT_PROCESS  00000000-0000-0000-0000-000000000000  SUBJECT_PROCESS EVENT_MPROTECT  1523543721467014633
```

Columns: `actorID | actor_type | objectID | object_type | action | timestampNanos`.

**Critical fact:** `actor_type` is **always `SUBJECT_PROCESS`** (only processes act).
Variation lives entirely in the *object* type. The 6 node-type classes the model
predicts (`DUMMIES` in `theia_flash_common.py`):

```
SUBJECT_PROCESS=0  MemoryObject=1  FILE_OBJECT_BLOCK=2
NetFlowObject=3    PRINCIPAL_REMOTE=4  PRINCIPAL_LOCAL=5
```

---

## 5. Node features — the token document

`add_attributes()` re-reads the raw split and merges `cmdLine` + path onto each edge,
then `prepare_graph()` builds, per node, a **document** = concatenation of
`[exec, action, path]` strings from every edge it touches.

**The token is the WHOLE string, not space-split.** A node's vocabulary entries look
like (real `word2vec` vocab dump):

```
/bin/bash -c /usr/bin/firefox
/bin/sh -c    cd / && run-parts --report /etc/cron.hourly
/usr/sbin/sshd -D -R
EVENT_MPROTECT
/etc/firefox/prefs.js
```

Consequences (this is the heart of how/why detection works):

- **Word2Vec** (`vector_size=30, window=5, min_count=1`) learns an embedding per
  distinct exec/action/path string. A node vector = **mean of its token embeddings**
  + positional encoding (`infer()`).
- Trained only on the **benign 1r period** → benign command lines are **in-vocab**,
  attacker command lines (`nc -e`, `wget http://…/tmp/.x`) are **OOV** → embed to
  `zeros(30)` = "never seen in baseline."
- Detection is **self-supervised node-type prediction**: a 20-round "explain-away"
  ensemble marks a node benign once the model confidently predicts its type. Survivors
  = anomalies/alerts.

> **Why single-event scoring is broken (your note):** a node's vector + the explain-away
> confidence are **batch-relative** (min/max normalized across the graph). One event = 1–2
> nodes = degenerate normalization = no signal. The model is a **sparse-seed anomaly
> detector that needs an accumulating graph**, not a per-event classifier. This is
> architectural, not a training defect — retraining will not fix it. The pipeline must
> window events into a graph and score nodes *in context*. See `plan.md` §single-event.

---

## 6. Ground truth

`data_files/theia.json` = flat JSON list of **25,359** malicious node UUIDs.

```json
["80370C6E-0ACA-FFFF-FFFF-000000000040", "", "80370C6E-75EA-FFFF-FFFF-000000000040", ...]
```

- Used **only at eval** (not in training — labels there are node *types*).
- ⚠️ Contains **empty-string `""` entries** (noise) — filter before set ops.
- Eval is **2-hop-adjusted**: an alert within 2 graph hops of a GT node counts as TP.
  This generous forgiveness is why headline recall ≈ 0.998; state it in the thesis.

---

## 7. CDM18 → live-collector mapping (bridge to the SIEM pipeline)

The live demo must produce the SAME representation. Rough equivalence for the §plan
normalizer (collector TBD — Sysmon-for-Linux / auditd / eBPF):

| Model needs | CDM18 source | Sysmon-for-Linux | auditd | eBPF (Tetragon) |
|---|---|---|---|---|
| actor process + `cmdLine` + `path` | `Subject.cmdLine`, `properties.map.path` | ProcessCreate (1) Image/CommandLine | `execve` a0..aN, `exe` | `process_exec` binary/args |
| FILE object + filename | `FileObject…filename` | FileCreate (11) TargetFilename | `path` name= | `process_kprobe` file |
| NET object + addrs/ports | `NetFlowObject` local/remote addr+port | NetworkConnect (3) Dst/SrcIp/Port | `connect` saddr | `process_connect` |
| action verb | `Event.type` (`EVENT_*`) | event id | syscall name | hook name |
| subject→object edge | `Event.subject`/`predicateObject` | PID → handle/target | pid → object | pid → arg |

**Hard part:** map the collector's verbs to the `EVENT_*` vocab AND keep cmdline/path
token strings close enough to the train vocab that benign live commands stay in-vocab.
Domain shift here = the make-or-break engineering risk (qualitative demo only, no second
recall number).
