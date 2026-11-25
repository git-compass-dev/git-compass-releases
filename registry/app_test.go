package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishApp(t *testing.T) {
	r, pub, _ := testRepo(t)
	publishVersion(t, r, "0.1.0") // a module, to check the catalog is left alone
	cat0, err := r.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mac := write("git-compass-0.3.0-macos-universal.zip", "app bundle")
	win := write("git-compass-0.3.0-windows-amd64-installer.exe", "installer")
	ix, err := r.PublishApp(AppInput{Version: "0.3.0", DownloadBase: "https://example.test/app-v0.3.0/",
		Files: map[string]string{"darwin/arm64": mac, "darwin/amd64": mac, "windows/amd64": win}, Notes: map[string]string{"tr": "Yeni"}})
	if err != nil {
		t.Fatal(err)
	}
	if ix.Latest != "0.3.0" || ix.Kind != KindAppIndex {
		t.Fatalf("index = %+v", ix)
	}
	f := ix.Versions[0].Files["darwin/arm64"]
	if f.URL != "https://example.test/app-v0.3.0/git-compass-0.3.0-macos-universal.zip" || f.Size != int64(len("app bundle")) || ix.Versions[0].Files["darwin/amd64"] != f {
		t.Fatalf("file = %+v", f)
	}
	// Signed, at app/index.json, with its own kind: it cannot pass as a module index.
	b, err := os.ReadFile(filepath.Join(r.Dir, "app", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Index
	if err := OpenDocument(b, []PublicKey{pub}, &got); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(AppID); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate("docker"); err == nil {
		t.Fatal("app index validated as a module index")
	}
	if _, err := r.PublishApp(AppInput{Version: "0.3.0", DownloadBase: "x", Files: map[string]string{"windows/amd64": win}}); err == nil {
		t.Fatal("republished an app version")
	}
	// The catalog is untouched; revoke and resign cover the app index.
	if c, _ := r.LoadCatalog(); c.Sequence != cat0.Sequence || len(c.Modules) != 1 {
		t.Fatalf("catalog changed: %+v", c)
	}
	if ix, err = r.Revoke(AppID, "0.3.0", "bad build"); err != nil || ix.Latest != "" {
		t.Fatalf("revoke: %v %+v", err, ix)
	}
	done, err := r.Resign()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range done {
		found = found || d == AppIndexPath
	}
	if !found {
		t.Fatalf("resign did not cover the app: %v", done)
	}
	// No module may take the app's id.
	m := mustManifest(t, "1.0.0")
	m.ID = AppID
	if _, err := r.Publish(PublishInput{Manifest: m, Artifacts: []Artifact{{Platform: "any", Name: "x.zip", SHA256: "00", Size: 1}}, DownloadBase: "x"}); err == nil {
		t.Fatal("module published under the app id")
	}
}
