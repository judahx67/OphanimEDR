"""
DARPA THEIA E3 log normalizer.

Converts raw CDM (Common Data Model) events from the THEIA dataset
into NormalizedEvent objects suitable for graph building.

THEIA CDM event types we care about:
  EVENT_FORK, EVENT_EXECUTE, EVENT_OPEN, EVENT_READ, EVENT_WRITE,
  EVENT_CLOSE, EVENT_CONNECT, EVENT_SENDTO, EVENT_RECVFROM,
  EVENT_MMAP, EVENT_RENAME, EVENT_UNLINK, EVENT_LOADLIBRARY,
  EVENT_MODIFY_FILE_ATTRIBUTES
"""

import logging
import uuid
from typing import Optional

from schema import EdgeType, NodeType, NormalizedEvent, ProvenanceNode

logger = logging.getLogger(__name__)

# ── THEIA CDM event type → our EdgeType ──────────────────────────────────

CDM_TO_EDGE: dict[str, EdgeType] = {
    "EVENT_FORK": EdgeType.FORK,
    "EVENT_CLONE": EdgeType.FORK,
    "EVENT_EXECUTE": EdgeType.EXEC,
    "EVENT_READ": EdgeType.READ,
    "EVENT_WRITE": EdgeType.WRITE,
    "EVENT_CONNECT": EdgeType.CONNECT,
    "EVENT_SENDTO": EdgeType.SEND,
    "EVENT_RECVFROM": EdgeType.RECEIVE,
    "EVENT_RECVMSG": EdgeType.RECEIVE,
    "EVENT_SENDMSG": EdgeType.SEND,
    "EVENT_MMAP": EdgeType.MMAP,
    "EVENT_RENAME": EdgeType.RENAME,
    "EVENT_UNLINK": EdgeType.DELETE,
    "EVENT_LOADLIBRARY": EdgeType.LOAD,
    "EVENT_MODIFY_FILE_ATTRIBUTES": EdgeType.WRITE,
}

# Events we skip (not causally relevant)
SKIP_EVENTS = {
    "EVENT_OPEN",
    "EVENT_CLOSE",
    "EVENT_CHECK_FILE_ATTRIBUTES",
    "EVENT_LSEEK",
    "EVENT_CHANGE_PRINCIPAL",
    "EVENT_LOGIN",
    "EVENT_LOGOUT",
    "EVENT_FCNTL",
    "EVENT_MPROTECT",
    "EVENT_SIGNAL",
    "EVENT_TRUNCATE",
    "EVENT_WAIT",
    "EVENT_EXIT",
    "EVENT_BIND",
    "EVENT_ACCEPT",
    "EVENT_OTHER",
    "EVENT_UPDATE",
    "EVENT_CREATE_OBJECT",
    # THEIA-specific chatter that isn't causally informative
    "EVENT_READ_SOCKET_PARAMS",
    "EVENT_WRITE_SOCKET_PARAMS",
    "EVENT_BOOT",
    "EVENT_SHM",
    "EVENT_FLOWS_TO",
    "EVENT_MODIFY_PROCESS",
    "EVENT_STARTSERVICE",
    "EVENT_ADD_OBJECT_ATTRIBUTE",
    "EVENT_FLUSH_PRIVILEGES",
}


class TheiaNodeCache:
    """
    Cache for resolving THEIA UUIDs to node info.

    THEIA datasets include Subject and Object datums that define entities.
    We cache these so when an Event datum references a subject/object UUID,
    we can resolve it to a proper ProvenanceNode.
    """

    def __init__(self):
        self._subjects: dict[str, dict] = {}  # uuid -> subject info
        self._objects: dict[str, dict] = {}    # uuid -> object (file/socket/etc) info

    def ingest_datum(self, datum: dict) -> None:
        """Cache a Subject or Object datum for later UUID resolution."""
        if "com.bbn.tc.schema.avro.cdm18.Subject" in datum:
            subj = datum["com.bbn.tc.schema.avro.cdm18.Subject"]
            uid = subj.get("uuid", "")
            self._subjects[uid] = subj
        elif "com.bbn.tc.schema.avro.cdm18.FileObject" in datum:
            obj = datum["com.bbn.tc.schema.avro.cdm18.FileObject"]
            uid = obj.get("uuid", "")
            obj["_obj_type"] = "FILE"
            self._objects[uid] = obj
        elif "com.bbn.tc.schema.avro.cdm18.NetFlowObject" in datum:
            obj = datum["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
            uid = obj.get("uuid", "")
            obj["_obj_type"] = "SOCKET"
            self._objects[uid] = obj
        elif "com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject" in datum:
            obj = datum["com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject"]
            uid = obj.get("uuid", "")
            obj["_obj_type"] = "PIPE"
            self._objects[uid] = obj
        elif "com.bbn.tc.schema.avro.cdm18.MemoryObject" in datum:
            obj = datum["com.bbn.tc.schema.avro.cdm18.MemoryObject"]
            uid = obj.get("uuid", "")
            obj["_obj_type"] = "MEMORY"
            self._objects[uid] = obj
        elif "com.bbn.tc.schema.avro.cdm18.RegistryKeyObject" in datum:
            obj = datum["com.bbn.tc.schema.avro.cdm18.RegistryKeyObject"]
            uid = obj.get("uuid", "")
            obj["_obj_type"] = "REGISTRY"
            self._objects[uid] = obj

    def resolve_subject(self, uuid_str: str) -> Optional[ProvenanceNode]:
        """Resolve a subject UUID to a ProvenanceNode (always a process)."""
        subj = self._subjects.get(uuid_str)
        if not subj:
            return None

        # Extract process info
        cmdline = subj.get("cmdLine", {})
        if isinstance(cmdline, dict):
            cmdline = cmdline.get("string", "") or ""
        if cmdline in ("N/A", "<unknown>"):
            cmdline = ""

        # THEIA stores the executable path inside properties.map.path
        exe_path = ""
        props_field = subj.get("properties") or {}
        if isinstance(props_field, dict):
            map_field = props_field.get("map") or props_field
            if isinstance(map_field, dict):
                exe_path = map_field.get("path", "") or map_field.get("name", "") or ""

        properties = {}
        if subj.get("cid") is not None:
            properties["pid"] = subj["cid"]
        if subj.get("parentSubject"):
            parent = subj["parentSubject"]
            if isinstance(parent, dict):
                properties["ppid_uuid"] = parent.get("com.bbn.tc.schema.avro.cdm18.UUID", "")
            else:
                properties["ppid_uuid"] = str(parent)
        if subj.get("localPrincipal"):
            properties["user_id"] = str(subj["localPrincipal"])
        if cmdline:
            properties["cmdline"] = cmdline
        if exe_path:
            properties["exe"] = exe_path

        # Prefer the executable path; fall back to cmdline; then placeholder
        name = exe_path or cmdline or f"process:{uuid_str[:12]}"

        return ProvenanceNode(
            node_type=NodeType.PROCESS,
            id=uuid_str,
            name=name,
            properties=properties,
        )

    def resolve_object(self, uuid_str: str) -> Optional[ProvenanceNode]:
        """Resolve an object UUID to a ProvenanceNode."""
        obj = self._objects.get(uuid_str)
        if not obj:
            return None

        obj_type_str = obj.get("_obj_type", "FILE")
        node_type = NodeType(obj_type_str)

        # Build name based on type
        if node_type == NodeType.SOCKET:
            local_addr = str(obj.get("localAddress", "") or "")
            local_port = obj.get("localPort", "") or ""
            remote_addr = str(obj.get("remoteAddress", "") or "")
            remote_port = obj.get("remotePort", "") or ""
            # THEIA uses "NA" as a sentinel for unset addresses
            has_remote = remote_addr and remote_addr != "NA"
            has_local = local_addr and local_addr not in ("NA", "LOCAL")
            if has_remote:
                name = f"{remote_addr}:{remote_port}"
            elif has_local:
                name = f"{local_addr}:{local_port}" if local_port else local_addr
            else:
                name = f"socket:{uuid_str[:12]}"
        elif node_type == NodeType.FILE:
            # THEIA stores filename at baseObject.properties.map.filename
            name = f"file:{uuid_str[:12]}"
            base = obj.get("baseObject")
            if isinstance(base, dict):
                bprops = base.get("properties")
                if isinstance(bprops, dict):
                    map_field = bprops.get("map") or bprops
                    if isinstance(map_field, dict):
                        name = (
                            map_field.get("filename")
                            or map_field.get("path")
                            or map_field.get("name")
                            or name
                        )
        elif node_type == NodeType.REGISTRY:
            name = obj.get("key", f"reg:{uuid_str[:12]}")
        elif node_type == NodeType.PIPE:
            name = f"pipe:{uuid_str[:12]}"
        elif node_type == NodeType.MEMORY:
            name = f"mem:{uuid_str[:12]}"
        else:
            name = f"{obj_type_str.lower()}:{uuid_str[:12]}"

        properties = {k: v for k, v in obj.items() if k != "_obj_type" and not k.startswith("_")}

        return ProvenanceNode(
            node_type=node_type,
            id=uuid_str,
            name=name,
            properties=properties,
        )

    @property
    def stats(self) -> dict:
        return {
            "cached_subjects": len(self._subjects),
            "cached_objects": len(self._objects),
        }


def normalize_event(datum: dict, cache: TheiaNodeCache) -> Optional[NormalizedEvent]:
    """
    Normalize a single THEIA CDM datum into a NormalizedEvent.

    Returns None if the datum is not an Event or is not causally relevant.
    """
    # First, always ingest Subject/Object datums into the cache
    cache.ingest_datum(datum)

    # Only process Event datums
    event_key = "com.bbn.tc.schema.avro.cdm18.Event"
    if event_key not in datum:
        return None

    event = datum[event_key]
    event_type = event.get("type", "")

    # Skip non-causal events
    if event_type in SKIP_EVENTS:
        return None

    edge_type = CDM_TO_EDGE.get(event_type)
    if edge_type is None:
        logger.debug("Unknown event type: %s", event_type)
        return None

    # Resolve subject and object
    subj_uuid = event.get("subject", {})
    if isinstance(subj_uuid, dict):
        subj_uuid = subj_uuid.get("com.bbn.tc.schema.avro.cdm18.UUID", "")
    subj_uuid = str(subj_uuid)

    obj_uuid = event.get("predicateObject", {})
    if isinstance(obj_uuid, dict):
        obj_uuid = obj_uuid.get("com.bbn.tc.schema.avro.cdm18.UUID", "")
    obj_uuid = str(obj_uuid)

    subject = cache.resolve_subject(subj_uuid)

    # FORK / CLONE: the child is itself a process, not a file/socket object.
    # In THEIA CDM18 the child UUID lives in `predicateObject`, NOT
    # `predicateObject2` — that field is usually the null UUID. Resolve
    # the child via the subject cache directly.
    if edge_type == EdgeType.FORK:
        obj = cache.resolve_subject(obj_uuid)
        if obj is None:
            # Child subject not yet cached — emit a placeholder so the
            # edge isn't lost. A later Subject datum with the same UUID
            # will MERGE into the same node in Neo4j.
            obj = ProvenanceNode(
                node_type=NodeType.PROCESS,
                id=obj_uuid,
                name=f"process:{obj_uuid[:12]}",
                properties={},
            )
    else:
        obj = cache.resolve_object(obj_uuid)

    if subject is None or obj is None:
        # Can't build edge without both endpoints
        return None

    # EXEC carries the real invocation command in properties.map.cmdLine.
    # Use it to enrich the subject process's name — the Subject datum's
    # cmdLine is often stale ("N/A") because it's set at process creation,
    # not at exec() time.
    if edge_type == EdgeType.EXEC:
        ev_props = event.get("properties") or {}
        if isinstance(ev_props, dict):
            pmap = ev_props.get("map") or ev_props
            if isinstance(pmap, dict):
                real_cmd = pmap.get("cmdLine") or ""
                if real_cmd and real_cmd != "N/A":
                    subject.properties["cmdline"] = real_cmd
                    # Show the cmdline as the display name if the cached
                    # name is just an executable path.
                    subject.name = real_cmd

    # Determine direction: for READ/RECEIVE, data flows object -> subject
    # but we keep subject as "who did it" and object as "what was acted on"

    timestamp = event.get("timestampNanos", 0)
    if isinstance(timestamp, dict):
        timestamp = timestamp.get("long", 0)

    event_uuid = event.get("uuid", str(uuid.uuid4()))

    size = event.get("size")
    if isinstance(size, dict):
        size = size.get("long") or size.get("int")

    properties = {}
    if event.get("name"):
        name_val = event["name"]
        if isinstance(name_val, dict):
            name_val = name_val.get("string", "")
        properties["name"] = name_val

    return NormalizedEvent(
        event_id=str(event_uuid),
        timestamp=int(timestamp),
        endpoint_id="theia-e3",
        edge_type=edge_type,
        subject=subject,
        object=obj,
        size=int(size) if size else None,
        properties=properties,
    )
