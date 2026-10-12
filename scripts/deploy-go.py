#!/usr/bin/env python3
"""Upgrade an existing B09 control plane with sandbox-built Linux Go binaries.

Configuration, OAuth records, certificates and the certbot environment stay in place.
The existing site bootstrap scripts are prerequisites. No build runs on the workstation
or hypervisor. Private rollback archives remain on their original hosts.
"""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--templates", type=Path,
                        help="Optional candidate templates.json to merge after immutable-template validation")
    args = parser.parse_args()
    names = ("carrel", "carrel-pve-read", "carrel-deployd")
    artifacts = args.artifacts.resolve()
    for name in names:
        if not (artifacts / name).is_file():
            raise SystemExit("Missing sandbox-built binary: " + name)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017 (macOS Python 3.9)
    stage = "/var/lib/carrel/go-upgrade-" + stamp
    run(["ssh", "carrel01", "install -d -m 700 " + stage])
    sources = [
        *(artifacts / name for name in names),
        ROOT / "scripts/node-agent.py",
        ROOT / "scripts/configure-go-reader.py",
    ]
    if args.templates:
        if args.templates.name != "templates.json":
            parser.error("candidate manifest must be named templates.json")
        sources.append(args.templates.resolve())
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    run(["scp", *map(str, sources), "carrel01:" + stage + "/"])
    preflight = """import sqlite3,json
c=sqlite3.connect('/var/lib/carrel/carrel.db')
active=[json.loads(v)['id'] for (v,) in c.execute("SELECT data FROM objects WHERE kind='operations'") if json.loads(v)['state'] not in ('succeeded','failed','rolled_back','cleanup_failed')]
assert not active, 'Active operations; retry deployment after completion'
print(json.dumps({'active_operations':len(active),'oauth_clients':c.execute("SELECT count(*) FROM oauth WHERE kind='client'").fetchone()[0]}))
"""
    backup = """import sqlite3,tarfile,os
from pathlib import Path
root=Path('/opt/carrel/rollback/go-STAMP');root.mkdir(parents=True,mode=0o700)
source=sqlite3.connect('/var/lib/carrel/carrel.db');target=sqlite3.connect(root/'carrel.db')
source.backup(target);target.close();source.close()
with tarfile.open(str(root)+'.tar.gz','w:gz') as archive:
 for name in ['/etc/carrel','/etc/systemd/system/carrel.service','/etc/systemd/system/carrel-backup.service','/var/lib/carrel/certificates','/usr/local/bin/carrel']:
  p=Path(name)
  if p.exists(): archive.add(p,arcname=name.lstrip('/'))
 archive.add(root/'carrel.db',arcname='var/lib/carrel/carrel.db')
os.chmod(str(root)+'.tar.gz',0o600)
for name in ['carrel.service','carrel-backup.service']:
 (root/name).write_bytes((Path('/etc/systemd/system')/name).read_bytes())
(root/'carrel.db').unlink()
""".replace("STAMP", stamp)
    activate = r"""from pathlib import Path
import json,os
for name,command in [('carrel.service','/usr/local/bin/carrel'),('carrel-backup.service','/usr/local/bin/carrel -backup')]:
 path=Path('/etc/systemd/system')/name
 lines=path.read_text().splitlines()
 assert sum(line.startswith('ExecStart=') for line in lines)==1
 path.write_text('\n'.join('ExecStart='+command if line.startswith('ExecStart=') else line for line in lines)+'\n')
os.replace('/usr/local/bin/carrel.next','/usr/local/bin/carrel')
path=Path('/etc/carrel/config.json'); config=json.loads(path.read_text())
manifest=json.loads(Path('/etc/carrel/templates.next.json').read_text())
environment=config.setdefault('vm_environment',{})
for image,entry in manifest.items():
 environment[image]={key:entry[key] for key in ['environment','packages','built_at','node_archive','node_sha256','sha256'] if key in entry}
path.write_text(json.dumps(config,indent=2)+'\n')
Path('/etc/carrel/templates.next.json').unlink()
"""
    program = f"""from pathlib import Path
import hashlib,json,os,shutil,subprocess,time,urllib.request
stage=Path({stage!r})
def ct(*args): subprocess.run(['pct','exec','100','--',*args],check=True)
def capture(*args): return subprocess.check_output(args,text=True)
for name,expected in {hashes!r}.items():
 assert hashlib.sha256((stage/name).read_bytes()).hexdigest()==expected, 'Transfer checksum mismatch'
template_path=Path('/etc/carrel/templates.json')
had_template_map=template_path.exists()
templates=json.loads(template_path.read_text()) if template_path.exists() else {{}}
if (stage/'templates.json').exists(): templates.update(json.loads((stage/'templates.json').read_text()))
minimal=templates.get('debian-13-minimal',{{}})
assert minimal.get('prepared') is True and minimal.get('environment')=='minimal', 'Install the prepared Debian minimal candidate before upgrading'
for image,entry in templates.items():
 vmid=entry['vmid']
 assert isinstance(vmid,int) and 9000<=vmid<=9999, 'Invalid template VMID'
 cfg=json.loads(capture('pvesh','get',f'/nodes/carrel01/qemu/{{vmid}}/config','--output-format','json'))
 assert cfg.get('template')==1 and cfg.get('scsi0','').startswith('local-lvm:base-'), 'Expected immutable LVM-thin template'
subprocess.run(['python3',str(stage/'configure-go-reader.py')],check=True)
# PVEAuditor alone silently hides volumes. Compare complete stable volume identities before enabling.
old=json.loads(capture('/usr/local/lib/carrel/pve-read.pl','inventory'))
new=json.loads(capture(str(stage/'carrel-pve-read'),'inventory'))
def volumes(value): return sorted((v['volid'],v['size']) for v in value['volumes'])
assert volumes(old)==volumes(new) and len(new['volumes'])>0, 'Incomplete HTTPS volume inventory'
ct('python3','-c',{preflight!r})
ct('systemctl','stop','carrel-backup.timer')
ct('systemctl','stop','carrel-backup.service')
ct('systemctl','stop','carrel')
activated=False
try:
 ct('python3','-c',{preflight!r})
 ct('python3','-c',{backup!r})
 for name,path in [('node-agent.py','/usr/local/lib/carrel/node-agent.py'),('node.json','/etc/carrel/node.json')]:
  shutil.copy2(path,stage/('before-'+name))
  os.chmod(stage/('before-'+name),0o600)
 if template_path.exists(): shutil.copy2(template_path,stage/'before-templates.json')
 template_next=stage/'templates.merged.json';template_next.write_text(json.dumps(templates,indent=2)+'\\n')
 subprocess.run(['install','-m','600',str(template_next),str(template_path)+'.next'],check=True)
 os.replace(str(template_path)+'.next',template_path)
 subprocess.run(['pct','push','100',str(template_next),'/etc/carrel/templates.next.json','--perms','600'],check=True)
 target=Path('/usr/local/lib/carrel/carrel-pve-read')
 if target.exists(): shutil.copy2(target,stage/'before-carrel-pve-read')
 subprocess.run(['install','-m','755',str(stage/'carrel-pve-read'),str(target)+'.next'],check=True)
 os.replace(str(target)+'.next',target)
 target=Path('/usr/local/lib/carrel/node-agent.py')
 subprocess.run(['install','-m','755',str(stage/'node-agent.py'),str(target)+'.next'],check=True)
 os.replace(str(target)+'.next',target)
 config=Path('/etc/carrel/node.json'); value=json.loads(config.read_text());value['go_pve_reader']=True
 config.write_text(json.dumps(value,indent=2)+'\\n')
 subprocess.run(['pct','push','100',str(stage/'carrel'),'/usr/local/bin/carrel.next','--perms','755'],check=True)
 # Served to tenant machines at /apps/v1/carrel-deployd (PLAN 7.9).
 ct('install','-d','-m','755','/usr/local/lib/carrel')
 subprocess.run(['pct','push','100',str(stage/'carrel-deployd'),'/usr/local/lib/carrel/carrel-deployd','--perms','755'],check=True)
 activated=True
 ct('python3','-c',{activate!r})
 ct('systemctl','daemon-reload')
 ct('systemctl','start','carrel')
 health=None
 for _ in range(30):
  try:
   request=urllib.request.Request('http://10.200.0.3:8080/healthz',headers={{'Host':'carrel.winlab.tw'}})
   health=json.load(urllib.request.urlopen(request,timeout=2))
   if health.get('version')=='0.9.0': break
  except (OSError,ValueError): pass
  time.sleep(1)
 assert health and health.get('version')=='0.9.0', 'Go health check failed'
 ct('systemctl','is-active','carrel')
 print(json.dumps({{'health':health,'volumes':len(new['volumes']),'node_backup':str(stage),'control_backup':'/opt/carrel/rollback/go-{stamp}.tar.gz'}}))
except BaseException:
 ct('systemctl','stop','carrel')
 if activated:
  restore="from pathlib import Path; import tarfile; a=tarfile.open('/opt/carrel/rollback/go-{stamp}.tar.gz'); names=['etc/systemd/system/carrel.service','etc/systemd/system/carrel-backup.service','etc/carrel/config.json','usr/local/bin/carrel']; [a.extract(n,'/',filter='data') for n in names if n in a.getnames()]"
  ct('python3','-c',restore)
 for name,path in [('node-agent.py','/usr/local/lib/carrel/node-agent.py'),('node.json','/etc/carrel/node.json')]:
  if (stage/('before-'+name)).exists(): shutil.copyfile(stage/('before-'+name),path)
 if (stage/'before-carrel-pve-read').exists(): shutil.copy2(stage/'before-carrel-pve-read','/usr/local/lib/carrel/carrel-pve-read')
 if (stage/'before-templates.json').exists(): shutil.copy2(stage/'before-templates.json',template_path)
 elif not had_template_map: template_path.unlink(missing_ok=True)
 ct('python3','-c',"from pathlib import Path; Path('/etc/carrel/templates.next.json').unlink(missing_ok=True)")
 ct('systemctl','daemon-reload')
 ct('systemctl','start','carrel')
 raise
finally:
 ct('systemctl','start','carrel-backup.timer')
"""
    run(["ssh", "carrel01", "python3 -"], input=program)
    revision = run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip()
    report = {
        "version": "0.9.0",
        "revision": revision,
        "stamp": stamp,
        "sha256": hashes,
        "node_backup": stage,
        "control_backup": "/opt/carrel/rollback/go-" + stamp + ".tar.gz",
    }
    (artifacts / "deploy-go.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
