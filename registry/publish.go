package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-compass-dev/git-compass-sdk/manifest"
)

// DocumentTTL is how long a signed index or catalog stays valid. The
// scheduled resign workflow refreshes everything well before that.
const DocumentTTL = 120 * 24 * time.Hour

// Repo is a checkout of the registry (git-compass-releases) on disk.
type Repo struct {
	Dir string
	Key ed25519.PrivateKey
	Now func() time.Time
}

func (r *Repo) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Repo) trusted() []PublicKey {
	pub := r.Key.Public().(ed25519.PublicKey)
	return []PublicKey{{ID: KeyID(pub), Key: pub}}
}

// LoadIndex reads and verifies a module index (a missing file is a new,
// empty index). A file this key did not sign is an error: the registry is
// never extended from a document we cannot vouch for.
func (r *Repo) LoadIndex(id string) (*Index, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("bad module id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, filepath.FromSlash(IndexPath(id))))
	if errors.Is(err, os.ErrNotExist) {
		return &Index{Kind: kindFor(id), Schema: Schema, ID: id}, nil
	}
	if err != nil {
		return nil, err
	}
	var ix Index
	if err := OpenDocument(b, r.trusted(), &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", IndexPath(id), err)
	}
	if err := ix.Validate(id); err != nil {
		return nil, err
	}
	return &ix, nil
}

// LoadCatalog reads and verifies the catalog (missing = empty).
func (r *Repo) LoadCatalog() (*Catalog, error) {
	b, err := os.ReadFile(filepath.Join(r.Dir, CatalogPath))
	if errors.Is(err, os.ErrNotExist) {
		return &Catalog{Kind: KindCatalog, Schema: Schema}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := OpenDocument(b, r.trusted(), &c); err != nil {
		return nil, fmt.Errorf("%s: %w", CatalogPath, err)
	}
	return &c, c.Validate()
}

// SaveIndex bumps sequence + expiry, recomputes latest, signs and writes.
func (r *Repo) SaveIndex(ix *Index) error {
	ix.Kind, ix.Schema = kindFor(ix.ID), Schema
	ix.Sequence++
	ix.Expires = r.now().Add(DocumentTTL).Truncate(time.Second)
	ix.SortVersions()
	ix.Latest = ix.ComputeLatest()
	if err := ix.Validate(ix.ID); err != nil {
		return err
	}
	b, err := SignDocument(ix, r.Key)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(r.Dir, filepath.FromSlash(IndexPath(ix.ID))), b)
}

// SaveCatalog bumps sequence + expiry, signs and writes.
func (r *Repo) SaveCatalog(c *Catalog) error {
	c.Kind, c.Schema = KindCatalog, Schema
	c.Sequence++
	c.Expires = r.now().Add(DocumentTTL).Truncate(time.Second)
	sort.Slice(c.Modules, func(i, j int) bool { return c.Modules[i].ID < c.Modules[j].ID })
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := SignDocument(c, r.Key)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(r.Dir, CatalogPath), b)
}

func writeFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// PublishInput is one new version.
type PublishInput struct {
	Manifest  manifest.Manifest
	Artifacts []Artifact
	// Archive URLs are DownloadBase + "/" + artifact name.
	DownloadBase string
	Notes        map[string]string
}

// Publish adds a version to its module index and refreshes the catalog.
// Published versions are immutable: publishing the same version twice fails.
func (r *Repo) Publish(in PublishInput) (*Index, error) {
	m := in.Manifest
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.ID == AppID {
		return nil, fmt.Errorf("publish: %q is reserved for the app", AppID)
	}
	if len(in.Artifacts) == 0 {
		return nil, errors.New("publish: no artifacts")
	}
	if in.DownloadBase == "" {
		return nil, errors.New("publish: download base URL is required")
	}
	ix, err := r.LoadIndex(m.ID)
	if err != nil {
		return nil, err
	}
	if ix.Find(m.Version) != nil {
		return nil, fmt.Errorf("publish: %s %s is already published (versions are immutable)", m.ID, m.Version)
	}
	rel := Release{
		Version:  m.Version,
		Type:     string(m.Type),
		SDK:      m.SDK,
		App:      m.App,
		Requires: m.Requires,
		Released: r.now().Truncate(time.Second),
		Notes:    in.Notes,
		Files:    map[string]File{},
	}
	base := strings.TrimRight(in.DownloadBase, "/")
	for _, a := range in.Artifacts {
		rel.Files[a.Platform] = File{URL: base + "/" + a.Name, SHA256: a.SHA256, Size: a.Size}
	}
	ix.Versions = append(ix.Versions, rel)
	if err := r.SaveIndex(ix); err != nil {
		return nil, err
	}
	return ix, r.updateCatalog(m, ix.Latest)
}

func (r *Repo) updateCatalog(m manifest.Manifest, latest string) error {
	c, err := r.LoadCatalog()
	if err != nil {
		return err
	}
	e := CatalogEntry{ID: m.ID, Type: string(m.Type), Group: m.Group, Name: m.Name, Description: m.Description, Latest: latest}
	found := false
	for i := range c.Modules {
		if c.Modules[i].ID == m.ID {
			// Name/description follow the newest published version only.
			if latest == m.Version || c.Modules[i].Name == nil {
				c.Modules[i] = e
			} else {
				c.Modules[i].Latest = latest
			}
			found = true
		}
	}
	if !found {
		c.Modules = append(c.Modules, e)
	}
	return r.SaveCatalog(c)
}

func (r *Repo) setLatestInCatalog(id, latest string) error {
	if id == AppID { // the app is not in the catalog
		return nil
	}
	c, err := r.LoadCatalog()
	if err != nil {
		return err
	}
	for i := range c.Modules {
		if c.Modules[i].ID == id {
			c.Modules[i].Latest = latest
		}
	}
	return r.SaveCatalog(c)
}

// Revoke marks a version revoked: clients disable it and refuse to install it.
func (r *Repo) Revoke(id, version, reason string) (*Index, error) {
	ix, err := r.LoadIndex(id)
	if err != nil {
		return nil, err
	}
	rel := ix.Find(version)
	if rel == nil {
		return nil, fmt.Errorf("revoke: %s %s is not published", id, version)
	}
	rel.Revoked, rel.RevokedReason = true, strings.TrimSpace(reason)
	if err := r.SaveIndex(ix); err != nil {
		return nil, err
	}
	return ix, r.setLatestInCatalog(id, ix.Latest)
}

// Unrevoke lifts a revocation (a mistaken revoke).
func (r *Repo) Unrevoke(id, version string) (*Index, error) {
	ix, err := r.LoadIndex(id)
	if err != nil {
		return nil, err
	}
	rel := ix.Find(version)
	if rel == nil {
		return nil, fmt.Errorf("unrevoke: %s %s is not published", id, version)
	}
	rel.Revoked, rel.RevokedReason = false, ""
	if err := r.SaveIndex(ix); err != nil {
		return nil, err
	}
	return ix, r.setLatestInCatalog(id, ix.Latest)
}

// SetMinVersion sets the security floor ("" clears it).
func (r *Repo) SetMinVersion(id, version string) (*Index, error) {
	ix, err := r.LoadIndex(id)
	if err != nil {
		return nil, err
	}
	if len(ix.Versions) == 0 {
		return nil, fmt.Errorf("min-version: %s has no published versions", id)
	}
	if version != "" {
		if _, err := manifest.ParseVersion(version); err != nil {
			return nil, err
		}
	}
	ix.MinVersion = version
	if err := r.SaveIndex(ix); err != nil {
		return nil, err
	}
	return ix, r.setLatestInCatalog(id, ix.Latest)
}

// Resign re-signs every index and the catalog with a fresh expiry.
func (r *Repo) Resign() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(r.Dir, "modules"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var done []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ix, err := r.LoadIndex(e.Name())
		if err != nil {
			return done, err
		}
		if len(ix.Versions) == 0 {
			continue
		}
		if err := r.SaveIndex(ix); err != nil {
			return done, err
		}
		done = append(done, IndexPath(ix.ID))
	}
	if app, err := r.LoadIndex(AppID); err != nil {
		return done, err
	} else if len(app.Versions) > 0 {
		if err := r.SaveIndex(app); err != nil {
			return done, err
		}
		done = append(done, AppIndexPath)
	}
	c, err := r.LoadCatalog()
	if err != nil {
		return done, err
	}
	if err := r.SaveCatalog(c); err != nil {
		return done, err
	}
	return append(done, CatalogPath), nil
}

// AppInput is one new release of the app itself.
type AppInput struct {
	Version string
	// platform ("darwin/arm64") → the update payload for it. Several
	// platforms may share one file (a universal macOS build).
	Files map[string]string
	// Payload URLs are DownloadBase + "/" + the file's base name.
	DownloadBase string
	Notes        map[string]string
}

// PublishApp adds an app release to app/index.json (not the catalog). Like
// module versions, app versions are immutable.
func (r *Repo) PublishApp(in AppInput) (*Index, error) {
	if _, err := manifest.ParseVersion(in.Version); err != nil {
		return nil, fmt.Errorf("publish-app: %w", err)
	}
	if len(in.Files) == 0 {
		return nil, errors.New("publish-app: no files")
	}
	if in.DownloadBase == "" {
		return nil, errors.New("publish-app: download base URL is required")
	}
	ix, err := r.LoadIndex(AppID)
	if err != nil {
		return nil, err
	}
	if ix.Find(in.Version) != nil {
		return nil, fmt.Errorf("publish-app: %s is already published (versions are immutable)", in.Version)
	}
	rel := Release{Version: in.Version, Type: "app", Released: r.now().Truncate(time.Second), Notes: in.Notes, Files: map[string]File{}}
	base := strings.TrimRight(in.DownloadBase, "/")
	for plat, p := range in.Files {
		if !strings.Contains(plat, "/") {
			return nil, fmt.Errorf("publish-app: bad platform %q", plat)
		}
		sum, size, err := HashFile(p)
		if err != nil {
			return nil, err
		}
		rel.Files[plat] = File{URL: base + "/" + filepath.Base(p), SHA256: sum, Size: size}
	}
	ix.Versions = append(ix.Versions, rel)
	return ix, r.SaveIndex(ix)
}
