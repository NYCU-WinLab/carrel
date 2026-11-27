// Package freeze is the freeze plugin: it parks a stopped carrel machine as a
// backup on the site's backup storage and brings it back (#664). This is the
// skeleton: it declares the operations and the object kind and probes the
// site, and no operation does work yet.
//
// It serves the plugin contract on the socket systemd passes as fd 3, and
// keeps its runs in $STATE_DIRECTORY. The environment names the API, the
// token, the node, the cluster CA and the storage to freeze to:
//
//	CARREL_PVE_URL        https://localhost:8006 unless set
//	CARREL_PVE_TOKEN      PVEAPIToken=<user>!<token>=<secret>
//	CARREL_PVE_NODE       the PVE node name, which can differ from the host name
//	CARREL_PVE_CA         /etc/carrel/plugins/freeze-ca.pem unless set
//	CARREL_BACKUP_STORAGE the backup storage; with none the site cannot freeze
package freeze

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// Version is set at build time.
var Version = "0.0.0-dev"

// noStorage is the reason carrel gives for a site without backup storage.
const noStorage = "The site has no backup storage (backup_storage) to freeze machines to"

type server struct {
	pluginpb.UnimplementedPluginServer
	pve *pve
	// storage is the backup storage, from CARREL_BACKUP_STORAGE.
	storage string
	// problem says why the plugin cannot run here, or "".
	problem string
	runs    store
	mu      sync.Mutex
	now     func() time.Time
}

const machineSchema = `"machine":{"type":"string","minLength":1,"maxLength":32}`

// Describe is what the plugin declares. The descriptions and schemas are
// those of machine_freeze and machine_thaw in internal/carrel/contract.json.
func Describe() *pluginpb.DescribeResponse {
	return &pluginpb.DescribeResponse{Name: "freeze", Version: Version, Contract: 1,
		Quota: []*pluginpb.QuotaDimension{{Name: "frozen_gb", DefaultLimit: 200, Unit: "GiB"}},
		Objects: []*pluginpb.ObjectKind{{Name: "frozen", Gone: true,
			Charges: []*pluginpb.Charge{{Dimension: "frozen_gb", Amount: 1, Per: "disk_gb"}}}},
		Operations: []*pluginpb.OperationType{
			{Name: "machine_freeze", Member: true, Toolset: "machines", DryRun: true, Idempotent: true,
				ObjectKind: "frozen", ObjectEffect: "create", ObjectParam: "machine", Stopped: true, Confirm: true,
				Description: "Park a stopped machine: carrel backs it up to the Proxmox Backup Server, verifies the backup and only then removes it from the cluster. " +
					"While frozen it releases vcpu, memory_mb, disk_gb and machines and charges its disk size to frozen_gb; its name, internal address, domains, ports and peers stay. " +
					"Refused unless the machine is shut down, has no disk snapshots, and has released any public IP, fixed public port or special domain it holds. " +
					"A failed or unverified backup leaves the machine untouched. The backup is the only copy: freezing is not an off-site backup. " +
					"confirm must equal the machine name. Bring it back with machine_thaw.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `,"confirm":{"type":"string","pattern":"^[a-z][a-z0-9-]{0,31}$"}},` +
					`"required":["machine","confirm"],"additionalProperties":false}`},
			{Name: "machine_thaw", Member: true, Toolset: "machines", DryRun: true,
				ObjectKind: "frozen", ObjectEffect: "delete", ObjectParam: "machine",
				Description: "Restore a frozen machine from its backup as a new machine with the same name and internal address. " +
					"Checks the normal quota like machine_create and fails with quota_exceeded when it is short; the machine comes back stopped, start it with machine_power. " +
					"Its backup is deleted and its frozen_gb released.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `},"required":["machine"],"additionalProperties":false}`},
		}}
}

func (s *server) Describe(context.Context, *pluginpb.DescribeRequest) (*pluginpb.DescribeResponse, error) {
	return Describe(), nil
}

func (s *server) Probe(ctx context.Context, _ *pluginpb.ProbeRequest) (*pluginpb.ProbeResponse, error) {
	if s.problem != "" {
		return &pluginpb.ProbeResponse{Reason: s.problem}, nil
	}
	if err := s.pve.version(ctx); err != nil {
		return &pluginpb.ProbeResponse{Reason: "the PVE API does not answer: " + err.Error()}, nil
	}
	// A token that signs in but lacks a privilege fails only when a member
	// uses it: the probe says so first.
	missing, err := s.pve.missing(ctx, s.storage)
	if err != nil {
		return &pluginpb.ProbeResponse{Reason: "the token's permissions cannot be read: " + err.Error()}, nil
	}
	if len(missing) > 0 {
		return &pluginpb.ProbeResponse{Reason: "the token lacks " + strings.Join(missing, ", ")}, nil
	}
	return &pluginpb.ProbeResponse{Supported: true}, nil
}

// StartOperation does nothing yet: machine_freeze and machine_thaw follow in
// the next sub-issues of #664.
func (s *server) StartOperation(context.Context, *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	return nil, status.Error(codes.Unimplemented, "the freeze plugin does not run operations yet")
}

// NewServer reads the environment. A plugin that cannot run here still
// answers Describe, and says why in Probe.
func NewServer() pluginpb.PluginServer { return newServer() }

func newServer() *server {
	s := &server{runs: store{dir: os.Getenv("STATE_DIRECTORY")}, now: time.Now,
		storage: strings.TrimSpace(os.Getenv("CARREL_BACKUP_STORAGE"))}
	base := os.Getenv("CARREL_PVE_URL")
	if base == "" {
		base = "https://localhost:8006"
	}
	ca := os.Getenv("CARREL_PVE_CA")
	if ca == "" {
		ca = "/etc/carrel/plugins/freeze-ca.pem"
	}
	token, node := os.Getenv("CARREL_PVE_TOKEN"), os.Getenv("CARREL_PVE_NODE")
	switch {
	case s.storage == "":
		s.problem = noStorage
	case s.runs.dir == "":
		s.problem = "no STATE_DIRECTORY"
	case token == "" || node == "":
		s.problem = "CARREL_PVE_TOKEN and CARREL_PVE_NODE must be set in /etc/carrel/plugins/freeze.env"
	default:
		p, err := newPVE(base, token, node, ca)
		if err != nil {
			s.problem = err.Error()
		}
		s.pve = p
	}
	return s
}

// Problem says why the server cannot run here, or "".
func Problem(p pluginpb.PluginServer) string {
	if s, ok := p.(*server); ok {
		return s.problem
	}
	return ""
}
