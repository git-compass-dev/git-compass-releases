// Command gcpack packs, signs and publishes Git Compass module packages.
//
//	gcpack keygen -out signing.key          new ed25519 key; prints the public key
//	gcpack pubkey                           public key of $GC_SIGNING_KEY
//	gcpack pack -pkg dist/pkg -out dist/zip one archive per platform (JSON on stdout)
//	gcpack publish -repo . -pkg dist/pkg -out dist/zip -download-base URL [-notes-en ..] [-notes-tr ..]
//	gcpack revoke -repo . -id docker -version 0.1.0 -reason "..."
//	gcpack unrevoke -repo . -id docker -version 0.1.0
//	gcpack min-version -repo . -id docker -version 0.2.0   ("" clears)
//	gcpack resign -repo .                   fresh expiry on every document
//	gcpack verify -repo . [-pubkey gcpk1:...]  check every document and its links
//
// Commands that sign read the private key from $GC_SIGNING_KEY ("gcsk1:…");
// it is never accepted as a flag so it cannot land in shell history or logs.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/git-compass-dev/git-compass-releases/registry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "pubkey":
		err = pubkey()
	case "pack":
		err = pack(os.Args[2:])
	case "publish":
		err = publish(os.Args[2:])
	case "publish-app":
		err = publishApp(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:], true)
	case "unrevoke":
		err = revoke(os.Args[2:], false)
	case "min-version":
		err = minVersion(os.Args[2:])
	case "resign":
		err = resign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gcpack:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gcpack keygen|pubkey|pack|publish|publish-app|revoke|unrevoke|min-version|resign|verify [flags]")
	os.Exit(2)
}

func signingRepo(dir string) (*registry.Repo, error) {
	k := os.Getenv("GC_SIGNING_KEY")
	if k == "" {
		return nil, errors.New("GC_SIGNING_KEY is not set")
	}
	key, err := registry.ParsePrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &registry.Repo{Dir: dir, Key: key}, nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the private key (created with mode 0600, must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required (the private key is never printed)")
	}
	pub, priv, err := registry.GenerateKey()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, registry.FormatPrivateKey(priv)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println(registry.FormatPublicKey(pub))
	fmt.Fprintf(os.Stderr, "private key written to %s (key id %s)\n", *out, registry.KeyID(pub))
	return nil
}

func pubkey() error {
	r, err := signingRepo(".")
	if err != nil {
		return err
	}
	pub := r.Key.Public().(ed25519.PublicKey)
	fmt.Printf("%s (key id %s)\n", registry.FormatPublicKey(pub), registry.KeyID(pub))
	return nil
}

func pack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	pkg := fs.String("pkg", "dist/pkg", "package folder (manifest.json, bin/, ui/)")
	out := fs.String("out", "dist/zip", "output folder")
	_ = fs.Parse(args)
	_, arts, err := registry.Pack(*pkg, *out)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(arts)
}

func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	pkg := fs.String("pkg", "dist/pkg", "package folder")
	out := fs.String("out", "dist/zip", "archive output folder")
	base := fs.String("download-base", "", "URL the archives will be served from (release download URL)")
	notesEN := fs.String("notes-en", "", "release notes (English)")
	notesTR := fs.String("notes-tr", "", "release notes (Turkish)")
	_ = fs.Parse(args)
	r, err := signingRepo(*repo)
	if err != nil {
		return err
	}
	m, arts, err := registry.Pack(*pkg, *out)
	if err != nil {
		return err
	}
	notes := map[string]string{}
	if *notesEN != "" {
		notes["en"] = *notesEN
	}
	if *notesTR != "" {
		notes["tr"] = *notesTR
	}
	if len(notes) == 0 {
		notes = nil
	}
	ix, err := r.Publish(registry.PublishInput{Manifest: m, Artifacts: arts, DownloadBase: *base, Notes: notes})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "published %s %s (index sequence %d, latest %s)\n", m.ID, m.Version, ix.Sequence, ix.Latest)
	for _, a := range arts {
		fmt.Println(a.Path)
	}
	return nil
}

// publishApp adds an app release: gcpack publish-app -version 0.3.0
// -download-base URL darwin/arm64=path darwin/amd64=path windows/amd64=path …
func publishApp(args []string) error {
	fs := flag.NewFlagSet("publish-app", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	ver := fs.String("version", "", "app version (x.y.z)")
	base := fs.String("download-base", "", "URL the files will be served from (release download URL)")
	notesEN := fs.String("notes-en", "", "release notes (English)")
	notesTR := fs.String("notes-tr", "", "release notes (Turkish)")
	_ = fs.Parse(args)
	files := map[string]string{}
	for _, a := range fs.Args() {
		plat, path, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("want platform=path, got %q", a)
		}
		files[plat] = path
	}
	r, err := signingRepo(*repo)
	if err != nil {
		return err
	}
	notes := map[string]string{}
	if *notesEN != "" {
		notes["en"] = *notesEN
	}
	if *notesTR != "" {
		notes["tr"] = *notesTR
	}
	if len(notes) == 0 {
		notes = nil
	}
	ix, err := r.PublishApp(registry.AppInput{Version: strings.TrimPrefix(*ver, "v"), Files: files, DownloadBase: *base, Notes: notes})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "published app %s (sequence %d, latest %s)\n", *ver, ix.Sequence, ix.Latest)
	return nil
}

func revoke(args []string, on bool) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	id := fs.String("id", "", "module id")
	ver := fs.String("version", "", "version")
	reason := fs.String("reason", "", "shown to users")
	_ = fs.Parse(args)
	r, err := signingRepo(*repo)
	if err != nil {
		return err
	}
	var ix *registry.Index
	if on {
		ix, err = r.Revoke(*id, *ver, *reason)
	} else {
		ix, err = r.Unrevoke(*id, *ver)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: sequence %d, latest %s\n", *id, ix.Sequence, ix.Latest)
	return nil
}

func minVersion(args []string) error {
	fs := flag.NewFlagSet("min-version", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	id := fs.String("id", "", "module id")
	ver := fs.String("version", "", "minimum version (empty clears)")
	_ = fs.Parse(args)
	r, err := signingRepo(*repo)
	if err != nil {
		return err
	}
	ix, err := r.SetMinVersion(*id, *ver)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: minVersion %q, sequence %d, latest %s\n", *id, ix.MinVersion, ix.Sequence, ix.Latest)
	return nil
}

func resign(args []string) error {
	fs := flag.NewFlagSet("resign", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	_ = fs.Parse(args)
	r, err := signingRepo(*repo)
	if err != nil {
		return err
	}
	done, err := r.Resign()
	for _, d := range done {
		fmt.Println(d)
	}
	return err
}

// verify checks every document against a public key (default: the one in
// keys/registry.pub) and that the catalog and indexes agree.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	repo := fs.String("repo", ".", "git-compass-releases checkout")
	pk := fs.String("pubkey", "", "public key (default: keys/registry.pub)")
	_ = fs.Parse(args)
	keyText := *pk
	if keyText == "" {
		b, err := os.ReadFile(filepath.Join(*repo, "keys", "registry.pub"))
		if err != nil {
			return fmt.Errorf("no -pubkey and keys/registry.pub: %w", err)
		}
		keyText = string(b)
	}
	var keys []registry.PublicKey
	for _, line := range strings.Split(keyText, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := registry.ParsePublicKey(line)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	now := time.Now()
	cb, err := os.ReadFile(filepath.Join(*repo, registry.CatalogPath))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no catalog yet")
		return nil
	}
	if err != nil {
		return err
	}
	var c registry.Catalog
	if err := registry.OpenDocument(cb, keys, &c); err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Expired(now) {
		return fmt.Errorf("catalog expired %s", c.Expires)
	}
	for _, e := range c.Modules {
		b, err := os.ReadFile(filepath.Join(*repo, filepath.FromSlash(registry.IndexPath(e.ID))))
		if err != nil {
			return err
		}
		var ix registry.Index
		if err := registry.OpenDocument(b, keys, &ix); err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
		if err := ix.Validate(e.ID); err != nil {
			return err
		}
		if ix.Expired(now) {
			return fmt.Errorf("%s: index expired %s", e.ID, ix.Expires)
		}
		if ix.Latest != e.Latest {
			return fmt.Errorf("%s: catalog latest %s, index latest %s", e.ID, e.Latest, ix.Latest)
		}
		fmt.Printf("%s ok: %d versions, latest %s, sequence %d, expires %s\n", e.ID, len(ix.Versions), ix.Latest, ix.Sequence, ix.Expires.Format(time.DateOnly))
	}
	fmt.Printf("catalog ok: %d modules, sequence %d\n", len(c.Modules), c.Sequence)
	if b, err := os.ReadFile(filepath.Join(*repo, filepath.FromSlash(registry.AppIndexPath))); err == nil {
		var ix registry.Index
		if err := registry.OpenDocument(b, keys, &ix); err != nil {
			return fmt.Errorf("app: %w", err)
		}
		if err := ix.Validate(registry.AppID); err != nil {
			return err
		}
		if ix.Expired(now) {
			return fmt.Errorf("app: index expired %s", ix.Expires)
		}
		fmt.Printf("app ok: %d versions, latest %s, sequence %d\n", len(ix.Versions), ix.Latest, ix.Sequence)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
