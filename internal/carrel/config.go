package carrel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"

	"golang.org/x/crypto/acme"
)

// Config is the control plane's configuration, /etc/carrel/config.json.
// It is decoded once at startup; an unknown key or a missing required value
// is a startup error, not an empty string at run time (#189). Sections that
// an integration reads on its own (netbox, vm_environment) stay maps until
// that integration moves to its own package.
type Config struct {
	Origin        string       `json:"origin"`
	Issuer        string       `json:"issuer"`
	Database      string       `json:"database"`
	PublicAddress string       `json:"public_address"`
	Nodes         []NodeConfig `json:"nodes"`
	SSHConfig     string       `json:"ssh_config,omitempty"`

	CloudflareZone  string `json:"cloudflare_zone,omitempty"`
	CloudflareToken string `json:"cloudflare_token,omitempty"`
	CloudflareAPI   string `json:"cloudflare_api,omitempty"`
	CertificateDir  string `json:"certificate_dir,omitempty"`
	ZoneDir         string `json:"zone_dir,omitempty"`
	ACMEDirectory   string `json:"acme_directory,omitempty"`
	ACMEEmail       string `json:"acme_email,omitempty"`

	HostedRedirects []string `json:"hosted_redirects,omitempty"`
	SSHJump         bool     `json:"ssh_jump,omitempty"`
	Fetch           bool     `json:"fetch,omitempty"`

	BackupStorage    string   `json:"backup_storage,omitempty"`
	FreezeRelease    []string `json:"freeze_release,omitempty"` // nil: the default list
	FreezeVerifyWait int      `json:"freeze_verify_wait,omitempty"`
	FrozenTotalGB    float64  `json:"frozen_total_gb,omitempty"`

	GuestReadyTimeout         int     `json:"guest_ready_timeout,omitempty"`
	ApplicationReadyTimeout   int     `json:"application_ready_timeout,omitempty"`
	GuestPollInterval         int     `json:"guest_poll_interval,omitempty"`
	MigrationSlotRetrySeconds float64 `json:"migration_slot_retry_seconds,omitempty"`
	MigrationBwlimitKiB       int     `json:"migration_bwlimit_kib,omitempty"`

	MaxPendingOperations       int `json:"max_pending_operations,omitempty"`
	MaxTenantPendingOperations int `json:"max_tenant_pending_operations,omitempty"`

	AppsDir               string `json:"apps_dir,omitempty"`
	AppsDiskHeadroomBytes *int64 `json:"apps_disk_headroom_bytes,omitempty"` // nil: diskHeadroom
	DeploydBinary         string `json:"deployd_binary,omitempty"`

	VMEnvironment D `json:"vm_environment,omitempty"`
	NetBox        D `json:"netbox,omitempty"`
}

// NodeConfig names a node and the SSH target that reaches it.
type NodeConfig struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// Defaults that the readers used to supply at each call site.
const (
	defaultCloudflareAPI  = "https://api.cloudflare.com/client/v4"
	defaultCertificateDir = "/var/lib/carrel/certificates"
	defaultZoneDir        = "/var/lib/carrel/zones"
	defaultAppsDir        = "/var/lib/carrel/apps"
	defaultDeploydBinary  = "/usr/local/lib/carrel/carrel-deployd"
	defaultFreezeWait     = 1800
	defaultGuestReady     = 900
	defaultAppReady       = 120
	defaultGuestPoll      = 3
	defaultSlotRetry      = 15.0
	defaultBwlimitKiB     = 51200
	defaultMaxPending     = 256
	defaultTenantPending  = 16
)

// LoadConfig decodes and validates a configuration file.
func LoadConfig(content []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid configuration: %w", err)
	}
	c = c.WithDefaults()
	return c, c.Validate()
}

// WithDefaults fills every optional value the control plane reads.
func (c Config) WithDefaults() Config {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	defInt := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.CloudflareAPI, defaultCloudflareAPI)
	def(&c.CertificateDir, defaultCertificateDir)
	def(&c.ZoneDir, defaultZoneDir)
	def(&c.AppsDir, defaultAppsDir)
	def(&c.DeploydBinary, defaultDeploydBinary)
	def(&c.ACMEDirectory, acme.LetsEncryptURL)
	defInt(&c.FreezeVerifyWait, defaultFreezeWait)
	defInt(&c.GuestReadyTimeout, defaultGuestReady)
	defInt(&c.ApplicationReadyTimeout, defaultAppReady)
	defInt(&c.GuestPollInterval, defaultGuestPoll)
	defInt(&c.MigrationBwlimitKiB, defaultBwlimitKiB)
	defInt(&c.MaxPendingOperations, defaultMaxPending)
	defInt(&c.MaxTenantPendingOperations, defaultTenantPending)
	if c.MigrationSlotRetrySeconds == 0 {
		c.MigrationSlotRetrySeconds = defaultSlotRetry
	}
	if c.VMEnvironment == nil {
		c.VMEnvironment = D{}
	}
	return c
}

// Validate is what main checks before anything opens (ValidateNodes before #189).
func (c Config) Validate() error {
	if ip, err := netip.ParseAddr(c.PublicAddress); err != nil || !ip.Is4() {
		return errors.New("public_address must be an IPv4 address")
	}
	if c.OriginHost() == "" {
		return errors.New("origin is required")
	}
	if c.Database == "" {
		return errors.New("database is required")
	}
	if len(c.Nodes) == 0 {
		return errors.New("nodes must list at least one node")
	}
	names, targets := map[string]bool{}, map[string]bool{}
	for _, n := range c.Nodes {
		if !nodeName.MatchString(n.Name) || !nodeName.MatchString(n.Target) {
			return errors.New("each node needs a name and an SSH target")
		}
		if names[n.Name] || targets[n.Target] {
			return fmt.Errorf("duplicate node %s", n.Name)
		}
		names[n.Name], targets[n.Target] = true, true
	}
	return nil
}

// OriginHost is the host name of carrel's public origin, such as carrel.winlab.tw.
func (c Config) OriginHost() string {
	u, err := url.Parse(c.Origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// AppsHeadroom is the free disk the apps store keeps.
func (c Config) AppsHeadroom() int64 {
	if c.AppsDiskHeadroomBytes != nil {
		return *c.AppsDiskHeadroomBytes
	}
	return diskHeadroom
}
