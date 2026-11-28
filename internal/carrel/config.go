package carrel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/crypto/acme"
)

// Config is the control plane's configuration, /etc/carrel/config.json.
// It is decoded once at startup; an unknown key or a missing required value
// is a startup error, not an empty string at run time (#189). Sections that
// an integration reads on its own (netbox, vm_environment) stay maps until
// that integration moves to its own package.
type Config struct {
	Origin string `json:"origin"`
	Issuer string `json:"issuer"`
	// OIDC names the claims and groups of the provider at Issuer (#654).
	OIDC          OIDCConfig `json:"oidc,omitempty"`
	Database      string     `json:"database"`
	PublicAddress string     `json:"public_address"`
	// SkillsHidden lists skills that skills_list and skill_get do not show,
	// so a bench can hide one for its control arm. It is server config, not a
	// tool argument, so the agent under test cannot see or change its arm.
	SkillsHidden []string `json:"skills_hidden,omitempty"`
	// Site names this control plane's site in catalog_get, such as b09.
	Site string `json:"site,omitempty"`
	// Domain is the site's own DNS zone: tenants get *.<slug>.<domain>.
	// Empty: winlab.tw.
	Domain string `json:"domain,omitempty"`
	// PublicHost is the name members reach SSH ports and the jump host
	// at. Empty: carrel.<domain>.
	PublicHost string       `json:"public_host,omitempty"`
	Nodes      []NodeConfig `json:"nodes"`
	SSHConfig  string       `json:"ssh_config,omitempty"`

	CloudflareZone  string `json:"cloudflare_zone,omitempty"`
	CloudflareToken string `json:"cloudflare_token,omitempty"`
	CloudflareAPI   string `json:"cloudflare_api,omitempty"`
	CertificateDir  string `json:"certificate_dir,omitempty"`
	ZoneDir         string `json:"zone_dir,omitempty"`
	ACMEDirectory   string `json:"acme_directory,omitempty"`
	ACMEEmail       string `json:"acme_email,omitempty"`

	// PortalKeysURL is the portal service that serves members' SSH keys,
	// e.g. https://portal.winlab.tw/api/ssh-keys/services/carrel, and
	// PortalKeysTokenFile holds its read key. Empty: creation never asks
	// the portal.
	PortalKeysURL       string `json:"portal_keys_url,omitempty"`
	PortalKeysTokenFile string `json:"portal_keys_token_file,omitempty"`

	// SSHUserCA is the lab SSH user CA public key, one authorized_keys line
	// (ca.winlab.tw). Set: every new VM and CT also trusts certificates it
	// signs for the creator's Keycloak username. Empty: keys only.
	SSHUserCA string `json:"ssh_user_ca,omitempty"`

	// KeycloakURL is the Keycloak base URL, e.g. https://sso.winlab.tw, and
	// KeycloakRealm, KeycloakClientID and KeycloakClientSecretFile name the
	// service client that may view users. All empty: no username resolves to
	// a sub. Partly set is a startup error.
	KeycloakURL              string `json:"keycloak_url,omitempty"`
	KeycloakRealm            string `json:"keycloak_realm,omitempty"`
	KeycloakClientID         string `json:"keycloak_client_id,omitempty"`
	KeycloakClientSecretFile string `json:"keycloak_client_secret_file,omitempty"`

	// TelemetryURL is any OTLP/HTTP collector, e.g. https://otel.example:4318:
	// WARN and ERROR log records, each node's capacity and one span per tool
	// call go to its /v1/logs, /v1/metrics and /v1/traces. TelemetryTokenFile
	// holds a bearer token, optional. Empty URL: nothing leaves the control plane.
	TelemetryURL       string `json:"telemetry_url,omitempty"`
	TelemetryTokenFile string `json:"telemetry_token_file,omitempty"`

	// IPv6Prefix is the site's tenant pool (issue #142, sites/<site>/cluster.json
	// ipv6.tenants, by default the first /48 of ipv6.prefix). Empty: machines
	// have IPv4 only and machine_create refuses ipv6.
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`

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
	// GitLabIssuers are the GitLab instances whose CI tokens can deploy an
	// app, as https origins. nil: gitlab.com only; [] turns GitLab off.
	GitLabIssuers []string `json:"gitlab_issuers,omitempty"`

	FunctionHosts []FunctionHostConfig `json:"function_hosts,omitempty"`
	// AgentListen is the address of the TLS listener node agents connect
	// to, such as 10.200.0.3:8443, with the certificate and key it serves.
	// Agents pin the CA of that certificate.
	AgentListen   string `json:"agent_listen,omitempty"`
	AgentCertFile string `json:"agent_cert_file,omitempty"`
	AgentKeyFile  string `json:"agent_key_file,omitempty"`
	// AgentClientCAFile is the lab root that agents' client certificates
	// chain to, and AgentProvisioner the credential id (key id) of the
	// step-ca provisioner that issues them (#601).
	AgentClientCAFile string `json:"agent_client_ca_file,omitempty"`
	AgentProvisioner  string `json:"agent_provisioner,omitempty"`
	// FunctionEnvKey encrypts functions' environment values at rest: 32
	// bytes in standard base64. Without it function_env is unavailable.
	FunctionEnvKey string `json:"function_env_key,omitempty"`
	// FunctionEnvOldKeys are earlier function_env_key values, in the same
	// form. They only open values; new values are sealed with
	// function_env_key. Keep an old key until nothing sealed with it is left.
	FunctionEnvOldKeys []string `json:"function_env_old_keys,omitempty"`

	// WebhookBlockedRanges are CIDR ranges webhooks must not reach, on top
	// of the private and reserved ones: the site's public pool and IPv6
	// prefix, for services that trust the lab's own addresses.
	WebhookBlockedRanges []string `json:"webhook_blocked_ranges,omitempty"`

	VMEnvironment D `json:"vm_environment,omitempty"`
	NetBox        D `json:"netbox,omitempty"`
}

// NodeConfig names a node and the SSH target that reaches it.
type NodeConfig struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	// Transport is how the control plane reaches the node: "ssh" (the
	// default) or "agent", where the node's carrel-agent connects out to
	// agent_listen and pulls its jobs (PLAN 8.6).
	Transport string `json:"transport,omitempty"`
	// AgentTokenSHA256 is the SHA-256 of the agent's token, and AgentSource
	// the address its connections come from; both must match.
	AgentTokenSHA256 string `json:"agent_token_sha256,omitempty"`
	AgentSource      string `json:"agent_source,omitempty"`
	// AgentCertificate is the name the agent's client certificate must
	// carry, such as carrel01.b09.agent.carrel.winlab.tw. When it is set the
	// agent signs in with that certificate and its token is refused (#601).
	AgentCertificate string `json:"agent_certificate,omitempty"`
}

// Defaults that the readers used to supply at each call site.
const (
	defaultCloudflareAPI  = "https://api.cloudflare.com/client/v4"
	defaultDomain         = "winlab.tw"
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
	def(&c.Domain, defaultDomain)
	def(&c.PublicHost, "carrel."+c.Domain)
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
	if c.GitLabIssuers == nil {
		c.GitLabIssuers = []string{gitlabCom}
	}
	c.OIDC = c.OIDC.WithDefaults()
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
	if c.Domain != "" && !zonePattern.MatchString(c.Domain) {
		return errors.New("domain must be a lower-case DNS name, such as winlab.tw")
	}
	// The gateway builds the origin site in the site's own zone, where its
	// certificate is issued, and refuses any other host (#794).
	if zone := or(c.Domain, defaultDomain); !under(c.OriginHost(), zone) || c.OriginHost() == zone {
		return errors.New("origin must be a host under domain, such as carrel." + zone)
	}
	if c.PublicHost != "" && !zonePattern.MatchString(c.PublicHost) {
		return errors.New("public_host must be a lower-case DNS name, such as carrel.winlab.tw")
	}
	if err := c.OIDC.Validate(); err != nil {
		return err
	}
	if c.IPv6Prefix != "" {
		if _, err := ipv6Prefix(c.IPv6Prefix); err != nil {
			return err
		}
	}
	// https only: the issuer's endpoints receive codes, refresh tokens and
	// the client secret, and its keys decide who is a member.
	if u, err := url.Parse(c.Issuer); c.Issuer != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "") {
		return errors.New("issuer must be an https URL with no query or fragment")
	}
	if c.Database == "" {
		return errors.New("database is required")
	}
	if len(c.Nodes) == 0 {
		return errors.New("nodes must list at least one node")
	}
	if c.PortalKeysURL != "" {
		// https only: the request carries the read key, and the answer
		// decides which keys a machine trusts.
		if u, err := url.Parse(c.PortalKeysURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return errors.New("portal_keys_url must be an https URL with no query")
		}
		if c.PortalKeysTokenFile == "" {
			return errors.New("portal_keys_url needs portal_keys_token_file")
		}
	}
	if c.SSHUserCA != "" && !sshUserCA.MatchString(c.SSHUserCA) {
		return errors.New("ssh_user_ca must be one SSH public key: type and base64, no comment")
	}
	if c.KeycloakURL != "" || c.KeycloakRealm != "" || c.KeycloakClientID != "" || c.KeycloakClientSecretFile != "" {
		// https only: the request carries the client secret.
		// "?" and "#" are refused as text: url.Parse accepts a bare "?" with an
		// empty RawQuery, which would move the route into the query.
		if u, err := url.Parse(c.KeycloakURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(c.KeycloakURL, "?#") || strings.Contains(c.KeycloakURL, "/.") {
			return errors.New("keycloak_url must be an https URL with no query, fragment or dot segment")
		}
		if c.KeycloakRealm == "" || c.KeycloakClientID == "" || c.KeycloakClientSecretFile == "" {
			return errors.New("keycloak_url needs keycloak_realm, keycloak_client_id and keycloak_client_secret_file")
		}
		if strings.ContainsAny(c.KeycloakRealm, "/?#\\%") || c.KeycloakRealm == "." || c.KeycloakRealm == ".." || url.PathEscape(c.KeycloakRealm) != c.KeycloakRealm {
			// The lookup sends url.PathEscape(realm); a realm that changes
			// under it (";", space) would not name the issuer's realm.
			return errors.New("keycloak_realm must be a single path segment")
		}
		// Tenant subjects come from tokens of Issuer, so the lookup must
		// address the same realm or no sub would ever match. NewApp trims
		// trailing slashes from Issuer, so compare the same form.
		if strings.TrimRight(c.KeycloakURL, "/")+"/realms/"+c.KeycloakRealm != strings.TrimRight(c.Issuer, "/") {
			return errors.New("keycloak_url and keycloak_realm must form the issuer: keycloak_url + /realms/ + keycloak_realm")
		}
	}
	if c.TelemetryURL != "" {
		u, err := url.Parse(c.TelemetryURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("telemetry_url must be an http or https URL with no query")
		}
		// A token never crosses the network in clear. Without one, http
		// suits a stock collector beside the control plane.
		if c.TelemetryTokenFile != "" && u.Scheme != "https" {
			return errors.New("telemetry_token_file needs an https telemetry_url")
		}
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
	hosts := map[string]bool{}
	for _, h := range c.FunctionHosts {
		if !functionHostName.MatchString(h.Name) || hosts[h.Name] {
			return fmt.Errorf("function host %q needs a unique name", h.Name)
		}
		if ap, err := netip.ParseAddrPort(h.Router); err != nil || !ap.Addr().Is4() {
			return fmt.Errorf("function host %s: router must be an IPv4 address and port", h.Name)
		}
		if !sha256Hex.MatchString(h.TokenSHA256) {
			return fmt.Errorf("function host %s: token_sha256 must be 64 lowercase hex digits", h.Name)
		}
		hosts[h.Name] = true
	}
	for _, issuer := range c.GitLabIssuers {
		u, err := url.Parse(issuer)
		// Tokens name their issuer exactly, so it must be written the one way
		// GitLab writes it: lower case, no query, fragment, dot segment or
		// trailing slash.
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(issuer, "?#") || strings.Contains(issuer, "/.") || strings.HasSuffix(issuer, "/") || issuer != strings.ToLower(issuer) || issuer == githubIssuer {
			return fmt.Errorf("gitlab_issuers: %q must be a lower-case https origin such as https://gitlab.com, with no trailing slash", issuer)
		}
	}
	if c.FunctionEnvKey != "" {
		if key, err := base64.StdEncoding.DecodeString(c.FunctionEnvKey); err != nil || len(key) != 32 {
			return fmt.Errorf("function_env_key must be 32 bytes in standard base64")
		}
	}
	for _, r := range c.WebhookBlockedRanges {
		if _, err := netip.ParsePrefix(r); err != nil {
			return fmt.Errorf("webhook_blocked_ranges: %q must be a CIDR range", r)
		}
	}
	agents := false
	for _, n := range c.Nodes {
		switch n.Transport {
		case "", "ssh":
		case "agent":
			agents = true
			// A node on certificate sign-in needs no token; a token given
			// must still be well formed.
			if (n.AgentCertificate == "" || n.AgentTokenSHA256 != "") && !sha256Hex.MatchString(n.AgentTokenSHA256) {
				return fmt.Errorf("node %s: agent_token_sha256 must be 64 lower-case hex characters", n.Name)
			}
			if _, err := netip.ParseAddr(n.AgentSource); err != nil {
				return fmt.Errorf("node %s: agent_source must be an IP address", n.Name)
			}
			if n.AgentCertificate != "" {
				if !agentName.MatchString(n.AgentCertificate) {
					return fmt.Errorf("node %s: agent_certificate must be a lower-case DNS name", n.Name)
				}
				if c.AgentClientCAFile == "" || c.AgentProvisioner == "" {
					return fmt.Errorf("node %s: agent_certificate needs agent_client_ca_file and agent_provisioner", n.Name)
				}
			}
		default:
			return fmt.Errorf("node %s: transport must be ssh or agent", n.Name)
		}
	}
	if agents && (c.AgentListen == "" || c.AgentCertFile == "" || c.AgentKeyFile == "") {
		return fmt.Errorf("a node on the agent transport needs agent_listen, agent_cert_file and agent_key_file")
	}
	if c.AgentClientCAFile != "" {
		if _, err := LoadCertPool(c.AgentClientCAFile); err != nil {
			return fmt.Errorf("agent_client_ca_file: %w", err)
		}
	}
	if c.AgentListen != "" {
		if _, err := netip.ParseAddrPort(c.AgentListen); err != nil {
			return fmt.Errorf("agent_listen must be an address and port, such as 10.200.0.3:8443")
		}
	}
	if len(c.FunctionEnvOldKeys) > 0 && c.FunctionEnvKey == "" {
		return fmt.Errorf("function_env_old_keys needs function_env_key")
	}
	for _, old := range c.FunctionEnvOldKeys {
		if key, err := base64.StdEncoding.DecodeString(old); err != nil || len(key) != 32 {
			return fmt.Errorf("function_env_old_keys: each key must be 32 bytes in standard base64")
		}
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
