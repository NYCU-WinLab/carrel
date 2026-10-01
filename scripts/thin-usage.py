"""Read a held LVM-thin metadata snapshot; count shared physical blocks once."""

import io
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def union(intervals):
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def length(intervals):
    return sum(end - start for start, end in union(intervals))


def retained(live, snapshots):
    # |live U snapshots| - |live|, not sum(Data%) and not sum per-snapshot sizes.
    return length([*live, *snapshots]) - length(live)


def account(xml, volumes, machines):
    owners = {m["vmid"]: m["tenant_n"] for m in machines}
    devices = {}
    for v in volumes:
        match = re.fullmatch(r"(snap_)?vm-(\d+)-(?:disk-\d+|cloudinit)(?:_.*)?", v["lv_name"])
        if match and int(match[2]) in owners and v.get("thin_id"):
            devices[int(v["thin_id"])] = (owners[int(match[2])], "snapshots" if match[1] else "live")
    ranges = {n: {"live": [], "snapshots": []} for n in set(owners.values())}
    current = None
    block_bytes = None
    for event, element in ET.iterparse(io.StringIO(xml), events=("start", "end")):
        if event == "start":
            if element.tag == "superblock":
                block_bytes = int(element.attrib["data_block_size"]) * 512
            elif element.tag == "device":
                current = devices.get(int(element.attrib["dev_id"]))
            elif current and element.tag in ("single_mapping", "range_mapping"):
                start = int(element.attrib["data_block"] if element.tag == "single_mapping" else element.attrib["data_begin"])
                size = 1 if element.tag == "single_mapping" else int(element.attrib["length"])
                ranges[current[0]][current[1]].append((start, start + size))
        elif event == "end":
            if element.tag == "device":
                current = None
            element.clear()
    if not block_bytes:
        raise ValueError("Missing metadata superblock")
    now = time.time()
    return [{"tenant_n": n, "sampled_at": now, "available": True,
             "retained_snapshot_bytes": retained(v["live"], v["snapshots"]) * block_bytes,
             "unique_total_bytes": length([*v["live"], *v["snapshots"]]) * block_bytes,
             "accounting": "union_of_snapshot_mappings_minus_live_mappings"} for n, v in ranges.items()]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout


def collect(machines):
    volumes = json.loads(run("lvs", "--reportformat", "json", "-o", "lv_name,thin_id", "pve"))["report"][0]["lv"]
    held = False
    try:
        run("dmsetup", "message", "/dev/mapper/pve-data-tpool", "0", "reserve_metadata_snap")
        held = True
        xml = run("thin_dump", "--metadata-snap", "/dev/mapper/pve-data_tmeta")
        return account(xml, volumes, machines)
    finally:
        if held:
            run("dmsetup", "message", "/dev/mapper/pve-data-tpool", "0", "release_metadata_snap")
