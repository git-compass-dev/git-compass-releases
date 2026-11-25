// Package registry is the module release format shared by gcpack (publishing)
// and git-compass-core (installing): signed per-module indexes, the signed
// catalog, package archives, compatibility and revocation rules.
//
// Layout under a registry base URL:
//
//	<base>/catalog.json              signed Catalog (every published module)
//	<base>/modules/<id>/index.json   signed Index (versions, files, revocations)
//
// Package archives are referenced by absolute URL + SHA-256 + size from the
// index, so the signature on the index covers every byte a client installs.
package registry

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/git-compass-dev/git-compass-sdk/manifest"
)

// Document kinds (inside the signed payload, so a catalog can never pass as
// an index and the other way round).
const (
	KindIndex   = "module-index"
	KindCatalog = "module-catalog"
	// The app's own releases (the core updater): same Index shape, its own
	// kind, never in the catalog.
	KindAppIndex = "app-index"
	Schema       = 1
)

// AppID is the index id of the Git Compass app itself (reserved: no module
// may use it). Its files are per platform: the update payload the app's
// updater downloads (macOS: zipped .app, Windows: installer, Linux: AppImage).
const AppID = "git-compass"

// AppIndexPath is where the app's index lives.
const AppIndexPath = "app/index.json"

// kindFor is the document kind of index id.
func kindFor(id string) string {
	if id == AppID {
		return KindAppIndex
	}
	return KindIndex
}

// AnyPlatform is the Files key for packages without binaries (themes, languages).
const AnyPlatform = "any"

// DefaultBaseURL is where the official registry lives.
const DefaultBaseURL = "https://raw.githubusercontent.com/git-compass-dev/git-compass-releases/main"

// IndexPath and CatalogPath are relative to a base URL or a checkout.
func IndexPath(id string) string {
	if id == AppID {
		return AppIndexPath
	}
	return "modules/" + id + "/index.json"
}

const CatalogPath = "catalog.json"

// File is one downloadable package archive.
type File struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Release is one published version of a module.
type Release struct {
	Version  string            `json:"version"`
	Type     string            `json:"type"`
	SDK      string            `json:"sdk,omitempty"`
	App      string            `json:"app,omitempty"`
	Requires map[string]string `json:"requires,omitempty"`
	Released time.Time         `json:"released"`
	// Short release notes per language.
	Notes map[string]string `json:"notes,omitempty"`
	// Revoked versions must not be installed or run.
	Revoked       bool   `json:"revoked,omitempty"`
	RevokedReason string `json:"revokedReason,omitempty"`
	// "linux/amd64" → archive, or "any" for packages without binaries.
	Files map[string]File `json:"files"`
}

// Index is everything published for one module.
type Index struct {
	Kind   string `json:"kind"`
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	// Strictly increasing per module; clients refuse an index older than the
	// last one they verified (rollback/freeze protection).
	Sequence int64     `json:"sequence"`
	Expires  time.Time `json:"expires"`
	// Newest non-revoked, non-prerelease version.
	Latest string `json:"latest,omitempty"`
	// Versions below this must not run (security floor).
	MinVersion string    `json:"minVersion,omitempty"`
	Versions   []Release `json:"versions"`
}

// CatalogEntry lists one module for the "available modules" screen.
type CatalogEntry struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Group       string            `json:"group,omitempty"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description,omitempty"`
	Latest      string            `json:"latest,omitempty"`
}

// Catalog is the list of published modules.
type Catalog struct {
	Kind     string         `json:"kind"`
	Schema   int            `json:"schema"`
	Sequence int64          `json:"sequence"`
	Expires  time.Time      `json:"expires"`
	Modules  []CatalogEntry `json:"modules"`
}

var (
	idRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidID reports whether s is a module id (same rule as manifests).
func ValidID(s string) bool { return idRe.MatchString(s) }

// Validate checks an index that claims to be module id.
func (ix *Index) Validate(id string) error {
	if want := kindFor(id); ix.Kind != want {
		return fmt.Errorf("index: kind %q, want %q", ix.Kind, want)
	}
	if ix.Schema != Schema {
		return fmt.Errorf("index: unsupported schema %d", ix.Schema)
	}
	if ix.ID != id || !ValidID(id) {
		return fmt.Errorf("index: id %q, want %q", ix.ID, id)
	}
	if ix.Sequence <= 0 {
		return errors.New("index: sequence must be positive")
	}
	if ix.MinVersion != "" {
		if _, err := manifest.ParseVersion(ix.MinVersion); err != nil {
			return fmt.Errorf("index: minVersion: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, r := range ix.Versions {
		if _, err := manifest.ParseVersion(r.Version); err != nil {
			return fmt.Errorf("index: %w", err)
		}
		if seen[r.Version] {
			return fmt.Errorf("index: version %s listed twice", r.Version)
		}
		seen[r.Version] = true
		if len(r.Files) == 0 {
			return fmt.Errorf("index: %s has no files", r.Version)
		}
		for plat, f := range r.Files {
			if plat != AnyPlatform && !strings.Contains(plat, "/") {
				return fmt.Errorf("index: %s: bad platform %q", r.Version, plat)
			}
			if !hexRe.MatchString(f.SHA256) || f.Size <= 0 || f.URL == "" {
				return fmt.Errorf("index: %s %s: bad file entry", r.Version, plat)
			}
		}
	}
	if ix.Latest != "" && !seen[ix.Latest] {
		return fmt.Errorf("index: latest %s not listed", ix.Latest)
	}
	return nil
}

// Validate checks a catalog.
func (c *Catalog) Validate() error {
	if c.Kind != KindCatalog {
		return fmt.Errorf("catalog: kind %q, want %q", c.Kind, KindCatalog)
	}
	if c.Schema != Schema {
		return fmt.Errorf("catalog: unsupported schema %d", c.Schema)
	}
	if c.Sequence <= 0 {
		return errors.New("catalog: sequence must be positive")
	}
	for _, m := range c.Modules {
		if !ValidID(m.ID) {
			return fmt.Errorf("catalog: bad id %q", m.ID)
		}
	}
	return nil
}

// Expired reports whether the document is past its expiry.
func (ix *Index) Expired(now time.Time) bool  { return !now.Before(ix.Expires) }
func (c *Catalog) Expired(now time.Time) bool { return !now.Before(c.Expires) }

// Find returns the release for version, or nil.
func (ix *Index) Find(version string) *Release {
	for i := range ix.Versions {
		if ix.Versions[i].Version == version {
			return &ix.Versions[i]
		}
	}
	return nil
}

// Blocked says why version must not run ("" = allowed): revoked, or below the
// security floor. A version the index does not list is not blocked (dev or
// side-loaded builds are judged by the developer-mode rules instead).
func (ix *Index) Blocked(version string) string {
	if r := ix.Find(version); r != nil && r.Revoked {
		if r.RevokedReason != "" {
			return "revoked: " + r.RevokedReason
		}
		return "revoked"
	}
	if ix.MinVersion != "" && Less(version, ix.MinVersion) {
		return "below minimum version " + ix.MinVersion
	}
	return ""
}

// Less compares two semver strings (unparsable sorts first).
func Less(a, b string) bool {
	va, ea := manifest.ParseVersion(a)
	vb, eb := manifest.ParseVersion(b)
	if ea != nil || eb != nil {
		return ea != nil && eb == nil
	}
	return va.Compare(vb) < 0
}

// IsPrerelease reports "1.2.0-beta.1" style versions.
func IsPrerelease(v string) bool {
	pv, err := manifest.ParseVersion(v)
	return err == nil && pv.Pre != ""
}

// SortVersions orders releases newest first.
func (ix *Index) SortVersions() {
	sort.SliceStable(ix.Versions, func(i, j int) bool { return Less(ix.Versions[j].Version, ix.Versions[i].Version) })
}

// ComputeLatest is the newest version that is not revoked, not a prerelease
// and not below MinVersion.
func (ix *Index) ComputeLatest() string {
	best := ""
	for _, r := range ix.Versions {
		if r.Revoked || IsPrerelease(r.Version) || ix.Blocked(r.Version) != "" {
			continue
		}
		if best == "" || Less(best, r.Version) {
			best = r.Version
		}
	}
	return best
}

// Env is what a client checks compatibility against.
type Env struct {
	// SDK contract version core speaks ("1.0.0").
	SDK string
	// App version ("dev" or "" skips the app range check).
	App string
	// Installed modules: id → version (for requires).
	Installed map[string]string
	// "linux/amd64".
	Platform string
}

// Incompatible says why r cannot run in env ("" = compatible).
func (r *Release) Incompatible(env Env) string {
	if r.Revoked {
		return "revoked"
	}
	if _, ok := r.Files[env.Platform]; !ok {
		if _, any := r.Files[AnyPlatform]; !any {
			return "no build for " + env.Platform
		}
	}
	if r.SDK != "" && env.SDK != "" {
		if ok, err := manifest.Satisfies(env.SDK, r.SDK); err != nil || !ok {
			return "needs SDK " + r.SDK
		}
	}
	if r.App != "" && env.App != "" && env.App != "dev" {
		if ok, err := manifest.Satisfies(strings.TrimPrefix(env.App, "v"), r.App); err != nil || !ok {
			return "needs app " + r.App
		}
	}
	ids := make([]string, 0, len(r.Requires))
	for id := range r.Requires {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		have, ok := env.Installed[id]
		if !ok {
			return "needs module " + id
		}
		if ok, err := manifest.Satisfies(have, r.Requires[id]); err != nil || !ok {
			return fmt.Sprintf("needs %s %s", id, r.Requires[id])
		}
	}
	return ""
}

// FileFor picks the archive for a platform (falls back to "any").
func (r *Release) FileFor(platform string) (File, bool) {
	if f, ok := r.Files[platform]; ok {
		return f, true
	}
	f, ok := r.Files[AnyPlatform]
	return f, ok
}
