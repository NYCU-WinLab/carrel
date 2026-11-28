package carrel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Forges are the CI systems whose OIDC tokens can deploy an app (PLAN 7.9,
// issue #265): GitHub Actions, and GitLab CI on gitlab.com or an instance the
// operator lists in gitlab_issuers. An app is bound to the pair (issuer,
// repository path), never to the path alone: anyone can run a GitLab instance
// and mint a token for any project_path, so a token counts only when its
// issuer is the one the app was linked to.

const (
	forgeGitHub = "github"
	forgeGitLab = "gitlab"
	gitlabCom   = "https://gitlab.com"
)

// CIClaims are what carrel reads of a forge's OIDC token, in GitHub's terms.
type CIClaims struct {
	Issuer       string
	Repository   string // lower case; a GitLab project path may have more than two segments
	RepositoryID string
	Ref          string // refs/heads/<branch> or refs/tags/<tag>
	SHA          string
	Event        string // GitHub event_name or GitLab pipeline_source
	RunURL       string
	// HeadRef is GitHub's head_ref on a pull_request run: the branch the
	// pull request comes from. It is the one claim that names the pull
	// request on every activity: the close of a merged pull request
	// carries the base branch as ref (#645).
	HeadRef string
	// BaseRef is GitHub's base_ref on a pull_request run: the branch the pull
	// request targets. A merged close must name the base the preview was
	// deployed against (#779).
	BaseRef string
	// RefProtected is GitLab's ref_protected: the ref is a protected branch
	// or tag. GitHub's token has no such claim.
	RefProtected bool
}

// Forge is the CI system that issued the token.
func (c CIClaims) Forge() string {
	if c.Issuer == githubIssuer {
		return forgeGitHub
	}
	return forgeGitLab
}

type OIDCVerifier interface {
	Verify(context.Context, string) (CIClaims, error)
}

// ForgeVerifier picks the verifier for a token's issuer. The unverified iss
// only chooses among issuers carrel already trusts; the chosen verifier
// checks the signature and the issuer again.
type ForgeVerifier struct {
	github *GitHubVerifier
	gitlab map[string]*GitLabVerifier
}

func NewForgeVerifier(audience string, gitlabIssuers []string) *ForgeVerifier {
	v := &ForgeVerifier{github: NewGitHubVerifier(audience), gitlab: map[string]*GitLabVerifier{}}
	for _, issuer := range gitlabIssuers {
		v.gitlab[issuer] = NewGitLabVerifier(issuer, audience)
	}
	return v
}

func (v *ForgeVerifier) Verify(ctx context.Context, token string) (CIClaims, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return CIClaims{}, err
	}
	iss := str(claims["iss"])
	if iss == githubIssuer {
		return v.github.Verify(ctx, token)
	}
	if g := v.gitlab[iss]; g != nil {
		return g.Verify(ctx, token)
	}
	return CIClaims{}, errors.New("untrusted issuer")
}

func parseOIDC(ctx context.Context, verifier *Verifier, token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return verifier.key(ctx, str(t.Header["kid"])) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(verifier.Audience), jwt.WithIssuer(verifier.Issuer), jwt.WithExpirationRequired(), jwt.WithLeeway(10*time.Second))
	return claims, err
}

type GitHubVerifier struct{ *Verifier }

func NewGitHubVerifier(audience string) *GitHubVerifier {
	return &GitHubVerifier{&Verifier{Issuer: githubIssuer, Audience: audience, JWKS: githubIssuer + "/.well-known/jwks", HTTP: &http.Client{Timeout: 8 * time.Second}}}
}

func (v *GitHubVerifier) Verify(ctx context.Context, token string) (CIClaims, error) {
	claims, err := parseOIDC(ctx, v.Verifier, token)
	if err != nil {
		return CIClaims{}, err
	}
	c := CIClaims{Issuer: githubIssuer, Repository: strings.ToLower(str(claims["repository"])), RepositoryID: str(claims["repository_id"]), Ref: str(claims["ref"]), SHA: str(claims["sha"]), Event: str(claims["event_name"]), HeadRef: str(claims["head_ref"]), BaseRef: str(claims["base_ref"])}
	if c.Repository == "" || c.RepositoryID == "" || c.Ref == "" {
		return CIClaims{}, errors.New("missing repository claims")
	}
	if id := str(claims["run_id"]); id != "" {
		c.RunURL = "https://github.com/" + str(claims["repository"]) + "/actions/runs/" + id
	}
	return c, nil
}

// GitLabVerifier checks ID tokens from one GitLab instance. Its keys are at
// <issuer>/oauth/discovery/keys, as its OIDC discovery document says.
type GitLabVerifier struct{ *Verifier }

func NewGitLabVerifier(issuer, audience string) *GitLabVerifier {
	return &GitLabVerifier{&Verifier{Issuer: issuer, Audience: audience, JWKS: issuer + "/oauth/discovery/keys", HTTP: &http.Client{Timeout: 8 * time.Second}}}
}

func (v *GitLabVerifier) Verify(ctx context.Context, token string) (CIClaims, error) {
	claims, err := parseOIDC(ctx, v.Verifier, token)
	if err != nil {
		return CIClaims{}, err
	}
	c := CIClaims{Issuer: v.Issuer, Repository: strings.ToLower(str(claims["project_path"])), RepositoryID: str(claims["project_id"]), Ref: str(claims["ref_path"]), SHA: str(claims["sha"]), Event: str(claims["pipeline_source"]), RefProtected: str(claims["ref_protected"]) == "true"}
	// Instances older than ref_path name the ref and its type apart.
	if c.Ref == "" && str(claims["ref"]) != "" {
		switch str(claims["ref_type"]) {
		case "branch":
			c.Ref = "refs/heads/" + str(claims["ref"])
		case "tag":
			c.Ref = "refs/tags/" + str(claims["ref"])
		}
	}
	if c.Repository == "" || c.RepositoryID == "" || c.Ref == "" {
		return CIClaims{}, errors.New("missing project claims")
	}
	if id := str(claims["job_id"]); id != "" {
		c.RunURL = v.Issuer + "/" + str(claims["project_path"]) + "/-/jobs/" + id
	}
	return c, nil
}

// deployEvents are the events that may deploy, per forge: a push to the
// branch, or a run started by hand on it.
var deployEvents = map[string][]string{
	forgeGitHub: {"push", "workflow_dispatch"},
	forgeGitLab: {"push", "web"},
}

// linkIssuer is the issuer an app or service was linked to. Records from
// before GitLab support have none and are GitHub's.
func linkIssuer(link D) string {
	if i := str(link["issuer"]); i != "" {
		return i
	}
	return githubIssuer
}

var (
	githubRepoRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	gitlabSegmentRE = regexp.MustCompile(`^[a-z0-9_][a-z0-9._-]{0,254}$`)
)

// parseRepo reads app_link's repo: a GitHub owner/name, or the web URL of a
// GitHub repository or of a project on an allowed GitLab instance. It returns
// the issuer and the lower-case path.
func parseRepo(repo string, gitlabIssuers []string) (string, string) {
	repo = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(repo)), "/"), ".git")
	if !strings.HasPrefix(repo, "https://") {
		if !githubRepo(repo) {
			fail("invalid", "repo must be a GitHub owner/name or a repository URL")
		}
		return githubIssuer, repo
	}
	if path, ok := strings.CutPrefix(repo, "https://github.com/"); ok {
		if !githubRepo(path) {
			fail("invalid", "A GitHub URL must name owner/name")
		}
		return githubIssuer, path
	}
	// The longest issuer first: with https://x.org and https://x.org/gitlab
	// both allowed, https://x.org/gitlab/a/b is a project of the second.
	issuers := append([]string(nil), gitlabIssuers...)
	sort.SliceStable(issuers, func(i, j int) bool { return len(issuers[i]) > len(issuers[j]) })
	for _, issuer := range issuers {
		path, ok := strings.CutPrefix(repo, strings.ToLower(issuer)+"/")
		if !ok {
			continue
		}
		segments := strings.Split(path, "/")
		if len(segments) < 2 || len(segments) > 20 {
			fail("invalid", "A GitLab URL must name group/project")
		}
		for _, s := range segments {
			if !gitlabSegmentRE.MatchString(s) {
				fail("invalid", "A GitLab URL must name group/project")
			}
		}
		return issuer, path
	}
	u, err := url.Parse(repo)
	host := repo
	if err == nil {
		host = u.Host
	}
	fail("invalid", fmt.Sprintf("%s is not an allowed GitLab instance; carrel accepts GitHub and %s", host, strings.Join(gitlabIssuers, ", ")))
	return "", ""
}

// githubRepo is an owner/name GitHub accepts; "." and ".." are no names.
func githubRepo(repo string) bool {
	_, name, _ := strings.Cut(repo, "/")
	return githubRepoRE.MatchString(repo) && name != "." && name != ".."
}

// repoURL is the web address of a linked repository.
func repoURL(link D) string {
	if issuer := linkIssuer(link); issuer != githubIssuer {
		return issuer + "/" + str(link["repo"])
	}
	return "https://github.com/" + str(link["repo"])
}

func linkForge(link D) string {
	return CIClaims{Issuer: linkIssuer(link)}.Forge()
}
