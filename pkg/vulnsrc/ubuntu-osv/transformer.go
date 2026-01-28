package ubuntuosv

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
)

type transformer struct{}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return adv, nil
}

// TransformAdvisories duplicates ESM advisories for non-ESM buckets.
// This ensures backward compatibility for users scanning regular Ubuntu versions.
func (t *transformer) TransformAdvisories(advs []osv.Advisory, _ osv.Entry) ([]osv.Advisory, error) {
	var result []osv.Advisory

	for _, adv := range advs {
		result = append(result, adv)

		// For ESM buckets, also create an advisory for the non-ESM bucket
		bucketName := adv.Bucket.Name()
		if strings.HasSuffix(bucketName, "-ESM") {
			version := strings.TrimSuffix(bucketName[len("ubuntu "):], "-ESM")
			nonESMAdv := adv
			nonESMAdv.Bucket = newBucket(version, source)
			result = append(result, nonESMAdv)
		}
	}

	return result, nil
}
