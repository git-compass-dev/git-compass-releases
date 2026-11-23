package registry

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-compass-dev/git-compass-sdk/manifest"
)

func newKey(t *testing.T) (ed25519.PrivateKey, PublicKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, PublicKey{ID: KeyID(pub), Key: pub}
}

func TestKeyTextRoundTrip(t *testing.T) {
	priv, pub := newKey(t)
	p2, err := ParsePrivateKey(FormatPrivateKey(priv))
	if err != nil || !bytes.Equal(p2, priv) {
		t.Fatalf("private round trip: %v", err)
	}
	k, err := ParsePublicKey(FormatPublicKey(pub.Key))
	if err != nil || k.ID != pub.ID || !bytes.Equal(k.Key, pub.Key) {
		t.Fatalf("public round trip: %v", err)
	}
	if _, err := ParsePublicKey("gcsk1:" + FormatPublicKey(pub.Key)[6:]); err == nil {
		t.Fatal("private prefix accepted as public key")
	}
	if _, err := ParsePrivateKey("gcsk1:AAAA"); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestSignOpen(t *testing.T) {
	priv, pub := newKey(t)
	_, other := newKey(t)
	doc := Catalog{Kind: KindCatalog, Schema: Schema, Sequence: 3, Modules: []CatalogEntry{{ID: "docker", Name: map[string]string{"en": "Docker"}}}}
	b, err := SignDocument(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	var got Catalog
	if err := OpenDocument(b, []PublicKey{pub}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 3 || got.Modules[0].ID != "docker" {
		t.Fatalf("payload: %+v", got)
	}
	// Rotation: any trusted key is enough.
	if err := OpenDocument(b, []PublicKey{other, pub}, &got); err != nil {
		t.Fatal(err)
	}
	if err := OpenDocument(b, []PublicKey{other}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("untrusted key: %v", err)
	}
	// Any change to the signed bytes breaks the signature, even whitespace.
	tampered := bytes.Replace(b, []byte(`"sequence": 3`), []byte(`"sequence": 4`), 1)
	if err := OpenDocument(tampered, []PublicKey{pub}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	ws := bytes.Replace(b, []byte(`"kind": "module-catalog"`), []byte(`"kind":  "module-catalog"`), 1)
	if err := OpenDocument(ws, []PublicKey{pub}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("whitespace change: %v", err)
	}
	// A signature cannot be moved to another key id.
	if err := OpenDocument([]byte(`{"signed":{"kind":"x"},"signatures":[]}`), []PublicKey{pub}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unsigned: %v", err)
	}
}

// writePkg makes a package folder like docker's scripts/package.sh output.
func writePkg(t *testing.T, version string, extra string) string {
	t.Helper()
	dir := t.TempDir()
	man := `{"id":"docker","version":"` + version + `","type":"module","name":{"en":"Docker"},"sdk":"^1.0",` + extra +
		`"binaries":{"linux/amd64":"bin/d-linux","windows/amd64":"bin/d.exe"},"ui":"ui/index.js"}`
	files := map[string]string{
		"manifest.json":  man,
		"bin/d-linux":    "ELF linux " + version,
		"bin/d.exe":      "MZ windows " + version,
		"ui/index.js":    "export default {}",
		"ui/chunks/a.js": "x",
	}
	for p, c := range files {
		fp := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func zipNames(t *testing.T, p string) []string {
	t.Helper()
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var out []string
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	return out
}

func TestPackExtract(t *testing.T) {
	pkg := writePkg(t, "1.0.0", "")
	out := t.TempDir()
	m, arts, err := Pack(pkg, out)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "docker" || len(arts) != 2 {
		t.Fatalf("pack: %s %v", m.ID, arts)
	}
	lin := arts[0]
	if lin.Platform != "linux/amd64" || lin.Name != "docker-1.0.0-linux-amd64.zip" {
		t.Fatalf("artifact: %+v", lin)
	}
	names := strings.Join(zipNames(t, lin.Path), ",")
	if names != "bin/d-linux,manifest.json,ui/chunks/a.js,ui/index.js" {
		t.Fatalf("linux archive holds %s", names)
	}
	// Deterministic: packing again gives the same bytes.
	_, again, err := Pack(pkg, t.TempDir())
	if err != nil || again[0].SHA256 != lin.SHA256 {
		t.Fatalf("not deterministic: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "docker", "1.0.0")
	em, err := Extract(lin.Path, dst, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if em.Version != "1.0.0" {
		t.Fatalf("extracted manifest %+v", em)
	}
	st, err := os.Stat(filepath.Join(dst, "bin", "d-linux"))
	if err != nil || st.Mode()&0o100 == 0 {
		t.Fatalf("binary not executable: %v %v", err, st)
	}
	if _, err := Extract(lin.Path, dst, "linux/amd64"); err == nil {
		t.Fatal("extract over an existing folder")
	}
	if _, err := Extract(arts[1].Path, filepath.Join(t.TempDir(), "x"), "linux/amd64"); err == nil {
		t.Fatal("windows archive extracted for linux")
	}
}

func TestPackMissingBinary(t *testing.T) {
	pkg := writePkg(t, "1.0.0", "")
	os.Remove(filepath.Join(pkg, "bin", "d.exe"))
	if _, _, err := Pack(pkg, t.TempDir()); err == nil {
		t.Fatal("packed without the windows binary")
	}
}

func TestPackTheme(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"id":"dark","version":"1.0.0","type":"theme","name":{"en":"Dark"},"themes":["dark.json"]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "dark.json"), []byte(`{}`), 0o644)
	_, arts, err := Pack(dir, t.TempDir())
	if err != nil || len(arts) != 1 || arts[0].Platform != AnyPlatform {
		t.Fatalf("theme pack: %v %+v", err, arts)
	}
	if _, err := Extract(arts[0].Path, filepath.Join(t.TempDir(), "d"), "linux/amd64"); err != nil {
		t.Fatal(err)
	}
}

func evilZip(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "evil.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	h := &zip.FileHeader{Name: name}
	h.SetMode(mode)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("x"))
	zw.Close()
	f.Close()
	return p
}

func TestExtractRefusesUnsafeEntries(t *testing.T) {
	for _, c := range []struct {
		name string
		mode os.FileMode
	}{
		{"../escape", 0o644},
		{"/abs", 0o644},
		{"a/../../escape", 0o644},
		{`a\..\escape`, 0o644},
		{"C:/x", 0o644},
		{"link", os.ModeSymlink | 0o777},
	} {
		dst := filepath.Join(t.TempDir(), "out")
		if _, err := Extract(evilZip(t, c.name, c.mode), dst, "linux/amd64"); err == nil {
			t.Errorf("%q extracted", c.name)
		}
	}
}

func testRepo(t *testing.T) (*Repo, PublicKey, *time.Time) {
	t.Helper()
	priv, pub := newKey(t)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	return &Repo{Dir: t.TempDir(), Key: priv, Now: func() time.Time { return now }}, pub, &now
}

func publishVersion(t *testing.T, r *Repo, version string) *Index {
	t.Helper()
	m, arts, err := Pack(writePkg(t, version, `"group":"dev",`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ix, err := r.Publish(PublishInput{Manifest: m, Artifacts: arts, DownloadBase: "https://example.test/releases/docker-v" + version})
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func readIndex(t *testing.T, r *Repo, pub PublicKey) Index {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.Dir, "modules", "docker", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ix Index
	if err := OpenDocument(b, []PublicKey{pub}, &ix); err != nil {
		t.Fatal(err)
	}
	if err := ix.Validate("docker"); err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestPublishRevokeMinVersion(t *testing.T) {
	r, pub, now := testRepo(t)
	publishVersion(t, r, "0.1.0")
	publishVersion(t, r, "0.2.0")
	publishVersion(t, r, "0.3.0-beta.1")
	ix := readIndex(t, r, pub)
	if ix.Sequence != 3 || ix.Latest != "0.2.0" || len(ix.Versions) != 3 || ix.Versions[0].Version != "0.3.0-beta.1" {
		t.Fatalf("after publish: seq %d latest %s versions %v", ix.Sequence, ix.Latest, ix.Versions)
	}
	f := ix.Find("0.2.0").Files["linux/amd64"]
	if f.URL != "https://example.test/releases/docker-v0.2.0/docker-0.2.0-linux-amd64.zip" || len(f.SHA256) != 64 {
		t.Fatalf("file entry %+v", f)
	}
	if !ix.Expires.Equal(now.Add(DocumentTTL)) {
		t.Fatalf("expires %s", ix.Expires)
	}
	if _, err := r.Publish(PublishInput{Manifest: mustManifest(t, "0.2.0"), Artifacts: []Artifact{{Platform: "any", Name: "x", SHA256: strings.Repeat("a", 64), Size: 1}}, DownloadBase: "https://x"}); err == nil {
		t.Fatal("republished 0.2.0")
	}

	if _, err := r.Revoke("docker", "0.2.0", "crashes on start"); err != nil {
		t.Fatal(err)
	}
	ix = readIndex(t, r, pub)
	if ix.Latest != "0.1.0" || ix.Blocked("0.2.0") != "revoked: crashes on start" || ix.Sequence != 4 {
		t.Fatalf("after revoke: latest %s blocked %q seq %d", ix.Latest, ix.Blocked("0.2.0"), ix.Sequence)
	}
	c, err := r.LoadCatalog()
	if err != nil || len(c.Modules) != 1 || c.Modules[0].Latest != "0.1.0" || c.Modules[0].Group != "dev" {
		t.Fatalf("catalog: %v %+v", err, c)
	}
	if _, err := r.Unrevoke("docker", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SetMinVersion("docker", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	ix = readIndex(t, r, pub)
	if ix.Latest != "0.2.0" || ix.Blocked("0.1.0") == "" || ix.Blocked("0.2.0") != "" || ix.Blocked("9.9.9") != "" {
		t.Fatalf("after min-version: latest %s", ix.Latest)
	}
	if _, err := r.Revoke("docker", "7.0.0", ""); err == nil {
		t.Fatal("revoked an unpublished version")
	}

	*now = now.Add(24 * time.Hour)
	done, err := r.Resign()
	if err != nil || len(done) != 2 {
		t.Fatalf("resign: %v %v", err, done)
	}
	ix2 := readIndex(t, r, pub)
	if ix2.Sequence != ix.Sequence+1 || !ix2.Expires.After(ix.Expires) {
		t.Fatalf("resign did not refresh: %d %s", ix2.Sequence, ix2.Expires)
	}
}

func mustManifest(t *testing.T, v string) manifest.Manifest {
	t.Helper()
	m2, _, err := Pack(writePkg(t, v, ""), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return m2
}

func TestPublishRefusesForeignIndex(t *testing.T) {
	r, _, _ := testRepo(t)
	publishVersion(t, r, "0.1.0")
	other, _ := newKey(t)
	r2 := &Repo{Dir: r.Dir, Key: other, Now: r.Now}
	if _, err := r2.LoadIndex("docker"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign key accepted: %v", err)
	}
	p := filepath.Join(r.Dir, "modules", "docker", "index.json")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(b, []byte("0.1.0"), []byte("0.1.1"), 1), 0o644)
	if _, err := r.LoadIndex("docker"); err == nil {
		t.Fatal("tampered index accepted")
	}
}

func TestIncompatible(t *testing.T) {
	r := Release{
		Version: "1.0.0", SDK: "^1.2", App: ">=2.0.0", Requires: map[string]string{"db": "^1.1"},
		Files: map[string]File{"linux/amd64": {}},
	}
	env := Env{SDK: "1.3.0", App: "2.1.0", Platform: "linux/amd64", Installed: map[string]string{"db": "1.4.0"}}
	if why := r.Incompatible(env); why != "" {
		t.Fatalf("compatible release refused: %s", why)
	}
	cases := map[string]func(e *Env){
		"no build for darwin/arm64": func(e *Env) { e.Platform = "darwin/arm64" },
		"needs SDK ^1.2":            func(e *Env) { e.SDK = "1.1.0" },
		"needs app >=2.0.0":         func(e *Env) { e.App = "1.9.0" },
		"needs module db":           func(e *Env) { e.Installed = nil },
		"needs db ^1.1":             func(e *Env) { e.Installed = map[string]string{"db": "1.0.0"} },
	}
	for want, mut := range cases {
		e := env
		mut(&e)
		if got := r.Incompatible(e); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
	dev := env
	dev.App = "dev"
	dev.SDK = "1.3.0"
	if got := r.Incompatible(dev); got != "" {
		t.Errorf("dev app build refused: %s", got)
	}
	r.Revoked = true
	if r.Incompatible(env) != "revoked" {
		t.Error("revoked release compatible")
	}
}
