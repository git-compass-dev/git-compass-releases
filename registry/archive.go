package registry

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-compass-dev/git-compass-sdk/manifest"
)

// Limits for archives a client extracts.
const (
	MaxArchiveSize   = 256 << 20 // download
	MaxUnpackedSize  = 512 << 20 // sum of files
	MaxArchiveFiles  = 20000
	archiveTimestamp = "2020-01-01T00:00:00Z"
)

// Artifact is one archive gcpack produced.
type Artifact struct {
	Platform string // "linux/amd64" or "any"
	Name     string // file name: <id>-<version>-<os>-<arch>.zip
	Path     string
	SHA256   string
	Size     int64
}

// ArchiveName is the file name of a package archive.
func ArchiveName(id, version, platform string) string {
	return fmt.Sprintf("%s-%s-%s.zip", id, version, strings.ReplaceAll(platform, "/", "-"))
}

// Pack turns a package folder (manifest.json + bin/… + ui/… as a module's
// scripts/package.sh with ALL=1 builds it) into one archive per platform in
// the manifest. Each archive holds the manifest, that platform's binary and
// every non-binary file. Packages without binaries get one "any" archive.
// Archives are deterministic (sorted entries, fixed timestamps).
func Pack(pkgDir, outDir string) (manifest.Manifest, []Artifact, error) {
	m, err := manifest.Load(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return m, nil, err
	}
	binaries := map[string]bool{}
	for plat, rel := range m.Binaries {
		p := filepath.Join(pkgDir, filepath.FromSlash(rel))
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return m, nil, fmt.Errorf("binary for %s missing: %s", plat, rel)
		}
		binaries[path.Clean(rel)] = true
	}
	var common []string
	err = filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files can be packed", p)
		}
		rel, _ := filepath.Rel(pkgDir, p)
		rel = filepath.ToSlash(rel)
		if !binaries[rel] {
			common = append(common, rel)
		}
		return nil
	})
	if err != nil {
		return m, nil, err
	}
	sort.Strings(common)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return m, nil, err
	}
	plats := make([]string, 0, len(m.Binaries))
	for p := range m.Binaries {
		plats = append(plats, p)
	}
	sort.Strings(plats)
	if len(plats) == 0 {
		plats = []string{AnyPlatform}
	}
	var out []Artifact
	for _, plat := range plats {
		files := append([]string{}, common...)
		if plat != AnyPlatform {
			files = append(files, path.Clean(m.Binaries[plat]))
			sort.Strings(files)
		}
		name := ArchiveName(m.ID, m.Version, plat)
		dst := filepath.Join(outDir, name)
		if err := writeZip(pkgDir, dst, files, m.Binaries[plat]); err != nil {
			return m, nil, err
		}
		sum, size, err := HashFile(dst)
		if err != nil {
			return m, nil, err
		}
		out = append(out, Artifact{Platform: plat, Name: name, Path: dst, SHA256: sum, Size: size})
	}
	return m, out, nil
}

func writeZip(root, dst string, files []string, exe string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	ts, _ := time.Parse(time.RFC3339, archiveTimestamp)
	zw := zip.NewWriter(f)
	for _, rel := range files {
		h := &zip.FileHeader{Name: rel, Method: zip.Deflate, Modified: ts}
		mode := fs.FileMode(0o644)
		if rel == path.Clean(exe) {
			mode = 0o755
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			f.Close()
			return err
		}
		src, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(w, src)
		src.Close()
		if err != nil {
			f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// HashFile returns the hex SHA-256 and size of a file.
func HashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Extract unpacks a verified archive into dst (which must not exist yet).
// It refuses absolute paths, "..", links and anything over the size limits,
// and marks the manifest's binary for this platform executable.
func Extract(archive, dst, platform string) (manifest.Manifest, error) {
	var m manifest.Manifest
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return m, err
	}
	defer zr.Close()
	if len(zr.File) > MaxArchiveFiles {
		return m, errors.New("archive: too many files")
	}
	if _, err := os.Stat(dst); err == nil {
		return m, fmt.Errorf("archive: %s already exists", dst)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return m, err
	}
	var total int64
	for _, zf := range zr.File {
		name := zf.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		clean := path.Clean(name)
		if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) || clean != name ||
			clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, ":") {
			return m, fmt.Errorf("archive: unsafe path %q", name)
		}
		if !zf.Mode().IsRegular() {
			return m, fmt.Errorf("archive: %q is not a regular file", name)
		}
		total += int64(zf.UncompressedSize64)
		if total > MaxUnpackedSize {
			return m, errors.New("archive: unpacked size over limit")
		}
		target := filepath.Join(dst, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return m, err
		}
		if err := extractOne(zf, target); err != nil {
			return m, err
		}
	}
	m, err = manifest.Load(filepath.Join(dst, "manifest.json"))
	if err != nil {
		return m, err
	}
	if m.RunsCode() {
		rel := m.Binaries[platform]
		if rel == "" {
			return m, fmt.Errorf("archive: no binary for %s", platform)
		}
		bin := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.Chmod(bin, 0o755); err != nil {
			return m, fmt.Errorf("archive: binary for %s: %w", platform, err)
		}
	}
	return m, nil
}

func extractOne(zf *zip.File, target string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	// Bound by the declared size so a lying header cannot fill the disk.
	n, err := io.Copy(out, io.LimitReader(rc, int64(zf.UncompressedSize64)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != int64(zf.UncompressedSize64) {
		return fmt.Errorf("archive: %q size mismatch", zf.Name)
	}
	return nil
}
