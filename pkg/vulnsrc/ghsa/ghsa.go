package ghsa

import (
	"encoding/json"
	"fmt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const ghsaDir = "ghsa"

var (
	sourceID   = vulnerability.GHSA
	ecosystems = []types.Ecosystem{
		vulnerability.Composer,
		vulnerability.Go,
		vulnerability.Maven,
		vulnerability.Npm,
		vulnerability.NuGet,
		vulnerability.Pip,
		vulnerability.RubyGems,
		vulnerability.Rust,
		vulnerability.Erlang,
		vulnerability.Pub,
		vulnerability.Swift,
	}
	platformFormat = "GitHub Security Advisory %s"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return sourceID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", ghsaDir)

	for _, ecosystem := range ecosystems {
		var entries []Entry
		err := utils.FileWalk(filepath.Join(rootDir, string(ecosystem)), func(r io.Reader, path string) error {
			var entry Entry
			if err := json.NewDecoder(r).Decode(&entry); err != nil {
				return xerrors.Errorf("failed to decode GHSA: %w", err)
			}
			entries = append(entries, entry)
			return nil
		})
		if err != nil {
			return xerrors.Errorf("error in GHSA walk: %w", err)
		}

		if err = vs.save(ecosystem, entries); err != nil {
			return xerrors.Errorf("error in GHSA save: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) save(ecosystem types.Ecosystem, entries []Entry) error {
	log.Printf("Saving GHSA %s", ecosystem)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ecosystem, entries)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, ecosystem types.Ecosystem, entries []Entry) error {
	ecosystemName := cases.Title(language.English).String(string(ecosystem))
	sourceName := fmt.Sprintf(platformFormat, ecosystemName)
	bucketName := bucket.Name(string(ecosystem), sourceName)
	err := vs.dbc.PutDataSource(tx, bucketName, types.DataSource{
		ID:   sourceID,
		Name: sourceName,
		URL:  fmt.Sprintf("https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s", ecosystem),
	})
	if err != nil {
		return xerrors.Errorf("failed to put data source: %w", err)
	}

	for _, entry := range entries {
		if entry.Advisory.WithdrawnAt != "" {
			continue
		}

		if ecosystem == vulnerability.Swift {
			// Swift uses `https://github.com/<author>/<package>.git format
			// But part Swift advisories doesn't `https://` prefix or `.git` suffix
			// e.g. https://github.com/github/advisory-database/blob/76f65b0d0fdac39c8b0e834ab03562b5f80d5b27/advisories/github-reviewed/2023/06/GHSA-qvxg-wjxc-r4gg/GHSA-qvxg-wjxc-r4gg.json#L21
			// https://github.com/github/advisory-database/blob/76f65b0d0fdac39c8b0e834ab03562b5f80d5b27/advisories/github-reviewed/2023/07/GHSA-jq43-q8mx-r7mq/GHSA-jq43-q8mx-r7mq.json#L21
			// Remove them to fit the same format
			entry.Package.Name = strings.TrimPrefix(entry.Package.Name, "https://")
			entry.Package.Name = strings.TrimSuffix(entry.Package.Name, ".git")
		}
		var pvs, avs []string
		for _, va := range entry.Versions {
			// e.g. GHSA-r4x3-g983-9g48 PatchVersion has "<" operator
			if strings.HasPrefix(va.FirstPatchedVersion.Identifier, "<") {
				va.VulnerableVersionRange = fmt.Sprintf(
					"%s, %s",
					va.VulnerableVersionRange,
					va.FirstPatchedVersion.Identifier,
				)
				va.FirstPatchedVersion.Identifier = strings.TrimPrefix(va.FirstPatchedVersion.Identifier, "< ")
			}

			if va.FirstPatchedVersion.Identifier != "" {
				pvs = append(pvs, va.FirstPatchedVersion.Identifier)
			}
			avs = append(avs, va.VulnerableVersionRange)
		}

		vulnID := entry.Advisory.GhsaId
		for _, identifier := range entry.Advisory.Identifiers {
			if identifier.Type == "CVE" && identifier.Value != "" {
				vulnID = identifier.Value
			}
		}
		vulnID = strings.TrimSpace(vulnID)

		a := types.Advisory{
			PatchedVersions:    pvs,
			VulnerableVersions: avs,
		}

		pkgName := vulnerability.NormalizePkgName(ecosystem, entry.Package.Name)

		err = vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{bucketName}, a)
		if err != nil {
			return xerrors.Errorf("failed to save GHSA: %w", err)
		}

		var references []string
		for _, ref := range entry.Advisory.References {
			references = append(references, ref.Url)
		}

		vuln := types.VulnerabilityDetail{
			ID:           vulnID,
			Severity:     severityFromThreat(entry.Severity),
			References:   references,
			Title:        entry.Advisory.Summary,
			Description:  entry.Advisory.Description,
			CvssScoreV3:  entry.Advisory.CVSS.Score,
			CvssVectorV3: entry.Advisory.CVSS.VectorString,
		}

		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, vulnerability.GHSA, vuln); err != nil {
			return xerrors.Errorf("failed to save GHSA vulnerability detail: %w", err)
		}

		// for optimization
		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}

	return nil
}

func severityFromThreat(urgency string) types.Severity {
	switch urgency {
	case "LOW":
		return types.SeverityLow
	case "MODERATE":
		return types.SeverityMedium
	case "HIGH":
		return types.SeverityHigh
	case "CRITICAL":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
