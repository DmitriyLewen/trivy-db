package ubuntunew

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
)

type transformer struct{}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return adv, nil
}

func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var result []osv.Advisory

	for _, aff := range entry.Affected {
		var commonFound, esmFound bool
		for _, v := range aff.Versions {
			if !strings.Contains(v, "+esm") {
				commonFound = true
				break
			}
			esmFound = true
		}
		if !commonFound && esmFound {
			fmt.Println(entry.ID)
		}
	}

	for _, adv := range advs {
		// Find the corresponding affected entry for this advisory
		var affected osv.Affected
		found := false
		for _, aff := range entry.Affected {
			if aff.Package.Name == adv.PkgName {
				affected = aff
				found = true
				break
			}
		}

		if !found {
			result = append(result, adv)
			continue
		}

		// Check if this is an ESM bucket
		bucketName := adv.Bucket.Name()
		isESM := strings.HasSuffix(bucketName, "-ESM")

		if !isESM {
			// Not an ESM bucket, keep as is
			result = append(result, adv)
			continue
		}

		// For ESM buckets, check if there are non-ESM versions
		hasNonESMVersions := false

		for _, version := range affected.Versions {
			if !strings.Contains(version, "+esm") {
				hasNonESMVersions = true
				break
			}
		}

		// Always add the ESM advisory
		result = append(result, adv)

		// If there are non-ESM versions, create an additional advisory for the non-ESM bucket
		if hasNonESMVersions {
			// Create a new bucket without the -ESM suffix
			version := strings.TrimSuffix(bucketName[len("ubuntu "):], "-ESM")
			nonESMAdv := adv
			nonESMAdv.Bucket = newBucket(version, source)
			result = append(result, nonESMAdv)
		}
	}

	return result, nil
}
