// ========================================================================
//  Ophanim-EDR — Demo queries for DARPA THEIA E3 provenance graph
// ========================================================================
//
// Paste these into the Neo4j Browser (http://localhost:7474) one at a time.
// Each query is designed to show *a specific story* from the real DARPA
// THEIA E3 dataset — not a random sample.
//
// The data loaded here is the first ~30,000 Event datums from
// ta1-theia-e3-official-1r.json.0, captured during a real Linux desktop
// session recorded by the DARPA Transparent Computing program in 2018.
//
// Why the default `MATCH ()-[]->() RETURN * LIMIT 100` looks terrible:
// it just grabs the first 100 edges, which are almost all MMAP/READ edges
// from a single boot-time python2.7 process loading shared libraries.
// That's one hub with 100 rays. Nothing interesting.
//
// The queries below constrain the projection so the visualizer only gets
// causally-meaningful slices of the graph.


// ------------------------------------------------------------------------
// 1. Graph summary — what does the dataset contain?
// ------------------------------------------------------------------------
// Expected: ~119 Process, ~1020 File, ~223 Socket, ~435 Memory nodes
//           with RECEIVE / READ / SEND / MMAP as the dominant edge types,
//           and much smaller counts of WRITE / CONNECT / FORK / EXEC.
// Use this to anchor the conversation before diving into any visualization.
MATCH (n) RETURN labels(n)[0] AS label, count(*) AS count ORDER BY count DESC;

MATCH ()-[r]->() RETURN type(r) AS edge, count(*) AS count ORDER BY count DESC;


// ------------------------------------------------------------------------
// 2. Process tree — who forked whom, with real command lines
// ------------------------------------------------------------------------
// This is the "meat" of provenance. Processes are enriched with the
// cmdLine captured on EVENT_EXECUTE, so you see the actual invocations
// (e.g. "dpkg --print-architecture", "sudo ./theia_toggle recording on")
// instead of just the binary path.
MATCH (parent:Process)-[f:FORK]->(child:Process)
RETURN parent, f, child;


// ------------------------------------------------------------------------
// 3. Exec chain — which processes exec'd what binaries
// ------------------------------------------------------------------------
// Every EXEC edge points from the process to the File it exec'd. This is
// the "what binary is now running in this PID slot" view.
MATCH (p:Process)-[e:EXEC]->(f:File)
RETURN p, e, f;


// ------------------------------------------------------------------------
// 4. Network activity — every process that opened a socket to the outside
// ------------------------------------------------------------------------
// Notable: most of the network traffic goes to 128.55.12.10:53 (DNS)
// via whoopsie, ubuntu-geoip-provider, and python. One connect targets
// 10.0.6.60 — internal LAN traffic. Real story, tiny graph.
MATCH (p:Process)-[c:CONNECT]->(s:Socket)
WHERE NOT s.name STARTS WITH 'socket:'  // skip unresolvable UNIX sockets
RETURN p, c, s;


// ------------------------------------------------------------------------
// 5. Sensitive file writes — what processes wrote to logs, history, /run
// ------------------------------------------------------------------------
// This surfaces sshd writing /run/utmp + /var/log/wtmp (login accounting),
// bash writing /home/darpa/.bash_history, console-kit-daemon writing its
// event history. In a real hunt, you'd look here for tampered auditd
// records or planted persistence.
MATCH (p:Process)-[w:WRITE]->(f:File)
WHERE f.name =~ '.*(log|history|utmp|wtmp|\\.ssh|cron|passwd|shadow).*'
RETURN p, w, f;


// ------------------------------------------------------------------------
// 6. "Who spawned what and then talked to the network" — the classic
//    EDR pivot: find processes that forked a child which then CONNECT'd.
// ------------------------------------------------------------------------
// This is the canonical lateral movement / C2 detection pattern.
MATCH (parent:Process)-[:FORK]->(child:Process)-[:CONNECT]->(s:Socket)
WHERE NOT s.name STARTS WITH 'socket:'
RETURN parent, child, s;


// ------------------------------------------------------------------------
// 7. Causal ancestry of a specific interesting process
// ------------------------------------------------------------------------
// Picks one leaf process by name and walks its entire provenance back
// through FORK edges. In this 30k-event slice, the longest chains are
// ~2 hops — to get deeper chains you need to replay more events so the
// normalizer can see older ancestors. Try changing the CONTAINS clause
// to "theia_toggle", "dpkg", or "sudo".
MATCH path = (ancestor:Process)-[:FORK*1..10]->(target:Process)
WHERE target.name CONTAINS 'apport-checkreports'
RETURN path;


// ------------------------------------------------------------------------
// 8. Per-process "blast radius" — what does process X touch?
// ------------------------------------------------------------------------
// Shows every file, socket, and child process touched by whoopsie
// (Ubuntu's crash reporter — one of the network-active processes in
// this slice). MMAP is excluded because whoopsie mmap'd hundreds of
// shared library pages on startup and they'd dominate the picture.
MATCH (p:Process {name: '/usr/bin/whoopsie'})-[r]->(target)
WHERE NOT type(r) IN ['MMAP', 'READ']
RETURN p, r, target;


// ------------------------------------------------------------------------
// 9. The biggest fan-out — which processes are the busiest?
// ------------------------------------------------------------------------
// Ranks processes by their total out-degree (reads, writes, sends, etc).
// Useful for spotting "noisy neighbors" and for explaining why a naive
// LIMIT 100 on the full graph looks like one gigantic hub.
MATCH (p:Process)-[r]->()
RETURN p.name AS process, count(r) AS out_degree
ORDER BY out_degree DESC
LIMIT 15;


// ------------------------------------------------------------------------
// 10. "Clean" subgraph for demo screenshots — process/file edges only,
//      no MMAP, no Memory nodes, capped so the layout stays readable.
// ------------------------------------------------------------------------
// This is the one to screenshot. It strips the visual noise and leaves
// the causal skeleton: processes executing binaries, forking children,
// reading/writing files, and connecting to sockets.
MATCH (p:Process)-[r:FORK|EXEC|WRITE|CONNECT|DELETE]->(target)
RETURN p, r, target
LIMIT 200;


// ------------------------------------------------------------------------
// 11. Reset — wipe the graph before re-running the simulator
// ------------------------------------------------------------------------
// Run this before `docker compose run --rm simulator --scenario theia ...`
// if you want a clean graph. The constraints / indexes are preserved.
// MATCH (n) DETACH DELETE n;
