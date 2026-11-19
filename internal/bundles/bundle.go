// Package bundles implements the signed offline-update bundle format
// specified in docs/offline-bundles.md: a gzip-compressed tar (".spb")
// containing a JSON MANIFEST listing payload files and their SHA-256s,
// a SIGNATURE member carrying Ed25519 signatures over the MANIFEST
// bytes, and the payload files themselves under payload/.
//
// The format exists for air-gapped appliances: staff generate a bundle
// for a published release (POST /v1/admin/releases/{id}/offline-bundle),
// carry it to the site and the appliance verifies the signature against
// its trust anchors before unpacking.
package bundles

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/technofish-au/sp-portal/internal/licensing"
)

// Wire member names inside the tarball.
const (
	ManifestMember  = "MANIFEST"
	SignatureMember = "SIGNATURE"
	// PayloadDir prefixes every payload file's tar member name.
	PayloadDir = "payload/"
)

// Kind is the manifest's format marker; Version is the manifest schema
// version (v1 — see docs/offline-bundles.md).
const (
	Kind    = "sp-offline-bundle"
	Version = 1
)

// ReleaseInfo is the release metadata embedded in the manifest so an
// appliance can decide whether the bundle applies to it.
type ReleaseInfo struct {
	Component      string `json:"component"`
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	MinUpgradeFrom string `json:"min_upgrade_from"`
	Security       bool   `json:"security"`
}

// FileEntry describes one payload file in the manifest. Path is the
// member name below payload/ (e.g. "artifact" or "docs/notes.txt").
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"` // lower-case hex
	Size   int64  `json:"size"`
}

// Manifest is the MANIFEST member's JSON content.
type Manifest struct {
	V         int         `json:"v"`
	Kind      string      `json:"kind"`
	CreatedAt time.Time   `json:"created_at"`
	Release   ReleaseInfo `json:"release"`
	Files     []FileEntry `json:"files"`
}

// File is one payload file to pack into the bundle.
type File struct {
	Path string    // member name under payload/
	Data io.Reader // exactly Size bytes are packed
}

// signatureEntry mirrors the licence document's rotation-slot shape so
// bundle verifiers reuse the same multi-key rule (any listed signature
// that verifies against a trusted kid is enough).
type signatureEntry struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Sig string `json:"sig"`
}

type signatureFile struct {
	Signatures []signatureEntry `json:"signatures"`
}

// Errors returned by Verify.
var (
	ErrBadBundle      = errors.New("bundles: not an offline bundle")
	ErrNoSignature    = errors.New("bundles: no signature verified")
	ErrBadManifest    = errors.New("bundles: manifest invalid")
	ErrMissingPayload = errors.New("bundles: payload file missing")
	ErrBadPayloadHash = errors.New("bundles: payload sha256 mismatch")
)

// Build writes a signed .spb bundle to w: MANIFEST (canonical-ish JSON —
// the signature covers the exact bytes written), SIGNATURE and every
// payload file under payload/. Each FileEntry in m.Files must have a
// matching File in files; SHA256/Size are computed while packing so the
// manifest always describes the bytes in the bundle.
func Build(w io.Writer, m Manifest, files []File, signer *licensing.Issuer) (retErr error) {
	if m.V == 0 {
		m.V = Version
	}
	if m.Kind == "" {
		m.Kind = Kind
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	defer func() {
		// Close order matters: tar footer, then gzip trailer.
		if err := tw.Close(); retErr == nil && err != nil {
			retErr = err
		}
		if err := gz.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()

	m.Files = make([]FileEntry, 0, len(files))
	contents := make([][]byte, len(files))
	for i, f := range files {
		data, err := io.ReadAll(f.Data)
		if err != nil {
			return fmt.Errorf("bundles: read %s: %w", f.Path, err)
		}
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, FileEntry{
			Path:   f.Path,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
		})
		contents[i] = data
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("bundles: manifest: %w", err)
	}
	if err := writeMember(tw, ManifestMember, raw); err != nil {
		return err
	}
	sig := signatureFile{Signatures: []signatureEntry{{
		KID: signer.KID(),
		Alg: licensing.AlgEd25519,
		Sig: base64.StdEncoding.EncodeToString(signer.SignRaw(raw)),
	}}}
	sigRaw, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	if err := writeMember(tw, SignatureMember, sigRaw); err != nil {
		return err
	}
	for i, f := range files {
		if err := writeMember(tw, PayloadDir+f.Path, contents[i]); err != nil {
			return err
		}
	}
	return nil
}

// Verified is a bundle whose signature and payload hashes checked out:
// the manifest plus the verified payload bytes keyed by member path.
type Verified struct {
	Manifest Manifest
	Payload  map[string][]byte
}

// Verify parses a .spb bundle, checks at least one SIGNATURE slot against
// trusted (kid -> Ed25519 pubkey) over the raw MANIFEST bytes, then
// verifies every payload file's sha256 and size against the manifest.
// Any tampering — signature, manifest or payload — is an error.
func Verify(r io.Reader, trusted map[string]ed25519.PublicKey) (*Verified, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", ErrBadBundle, err)
	}
	defer func() { _ = gz.Close() }()
	var manifestRaw, sigRaw []byte
	payload := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrBadBundle, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("%w: read %s: %v", ErrBadBundle, hdr.Name, err)
		}
		switch {
		case hdr.Name == ManifestMember:
			manifestRaw = data
		case hdr.Name == SignatureMember:
			sigRaw = data
		case len(hdr.Name) > len(PayloadDir) && hdr.Name[:len(PayloadDir)] == PayloadDir:
			payload[hdr.Name[len(PayloadDir):]] = data
		}
	}
	if len(manifestRaw) == 0 || len(sigRaw) == 0 {
		return nil, ErrBadBundle
	}
	var sig signatureFile
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrBadBundle, err)
	}
	verified := false
	for _, e := range sig.Signatures {
		pub, ok := trusted[e.KID]
		if !ok || e.Alg != licensing.AlgEd25519 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, manifestRaw, raw) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrNoSignature
	}
	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if m.V != Version || m.Kind != Kind {
		return nil, fmt.Errorf("%w: unsupported kind %q v%d", ErrBadManifest, m.Kind, m.V)
	}
	for _, fe := range m.Files {
		data, ok := payload[fe.Path]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingPayload, fe.Path)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != fe.SHA256 || int64(len(data)) != fe.Size {
			return nil, fmt.Errorf("%w: %s", ErrBadPayloadHash, fe.Path)
		}
	}
	return &Verified{Manifest: m, Payload: payload}, nil
}

// writeMember appends one regular file to the tar stream.
func writeMember(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0o640,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("bundles: tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("bundles: tar write %s: %w", name, err)
	}
	return nil
}
