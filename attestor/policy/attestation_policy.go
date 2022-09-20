// Copyright 2021 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/gobwas/glob"
	"gopkg.in/yaml.v2"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
)

//nolint:govet
type AttestationPolicy struct {
	// PreventBinaryArtifacts : set to true to require that this project's SCM repo is
	// free of binary artifacts
	PreventBinaryArtifacts bool `yaml:"preventBinaryArtifacts"`

	// AllowedBinaryArtifacts : List of binary artifact paths to ignore
	// when checking for binary artifacts in a repo
	AllowedBinaryArtifacts []string `yaml:"allowedBinaryArtifacts"`

	// EnsureNoVulnerabilities : set to true to require that this project is free
	// of vulnerabilities, as discovered from the OSV service
	EnsureNoVulnerabilities bool `yaml:"ensureNoVulnerabilities"`

	// EnsureDependenciesPinned : set to true to require that this project pin dependencies
	// by hash/commit SHA
	EnsureDependenciesPinned bool `yaml:"ensureDependenciesPinned"`

	// AllowedUnpinnedDependencies : set of dependencies to ignore when checking for
	// unpinned dependencies
	AllowedUnpinnedDependencies []Dependency `yaml:"allowedUnpinnedDependencies"`

	// EnsureCodeReviewed : set to true to require that the most recent commits in
	// this project have gone through a code review process
	EnsureCodeReviewed bool `yaml:"ensureCodeReviewed"`

	// CodeReviewRequirements : define specific code review requirements that the default
	// branch must have met, e.g. required approvers
	ReviewRequirements CodeReviewRequirements `yaml:"codeReviewRequirements"`
}

type CodeReviewRequirements struct {
	RequiredApprovers []string `yaml:"requiredApprovers"`
	MinReviewers      int      `yaml:"minReviewers"`
}

type Dependency struct {
	Filepath    string `yaml:"filepath"`
	PackageName string `yaml:"packagename"`
	Version     string `yaml:"version"`
}

// Allows us to run fewer scorecard checks if some policy values
// are don't-cares.
func (ap *AttestationPolicy) GetRequiredChecksForPolicy() map[string]bool {
	requiredChecks := make(map[string]bool)

	if ap.PreventBinaryArtifacts {
		requiredChecks["BinaryArtifacts"] = true
	}

	if ap.EnsureNoVulnerabilities {
		requiredChecks["Vulnerabilities"] = true
	}

	if ap.EnsureCodeReviewed {
		requiredChecks["CodeReview"] = true
	}

	if ap.EnsureDependenciesPinned {
		requiredChecks["PinnedDependencies"] = true
	}

	return requiredChecks
}

// Run attestation policy checks on raw data.
func (ap *AttestationPolicy) EvaluateResults(raw *checker.RawResults) (PolicyResult, error) {
	dl := checker.NewLogger()
	if ap.PreventBinaryArtifacts {
		checkResult, err := CheckPreventBinaryArtifacts(ap.AllowedBinaryArtifacts, raw, dl)
		if !checkResult || err != nil {
			return checkResult, err
		}
	}

	if ap.EnsureDependenciesPinned {
		checkResult, err := CheckNoUnpinnedDependencies(ap.AllowedUnpinnedDependencies, raw, dl)
		if !checkResult || err != nil {
			return checkResult, err
		}
	}

	if ap.EnsureNoVulnerabilities {
		checkResult, err := CheckNoVulnerabilities(raw, dl)
		if !checkResult || err != nil {
			return checkResult, err
		}
	}

	if ap.EnsureCodeReviewed {
		// By default, if code review reqs. aren't specified, we assume
		// the user wants there to be atleast one reviewer
		if len(ap.ReviewRequirements.RequiredApprovers) == 0 &&
			ap.ReviewRequirements.MinReviewers == 0 {
			ap.ReviewRequirements.MinReviewers = 1
		}

		checkResult, err := CheckCodeReviewed(ap.ReviewRequirements, raw, dl)
		if !checkResult || err != nil {
			return checkResult, err
		}
	}

	return Pass, nil
}

type PolicyResult = bool

const (
	Pass PolicyResult = true
	Fail PolicyResult = false
)

func CheckPreventBinaryArtifacts(
	allowedBinaryArtifacts []string,
	results *checker.RawResults,
	dl checker.DetailLogger,
) (PolicyResult, error) {
	for i := range results.BinaryArtifactResults.Files {
		artifactFile := results.BinaryArtifactResults.Files[i]

		ignoreArtifact := false

		for j := range allowedBinaryArtifacts {
			allowGlob := allowedBinaryArtifacts[j]

			if g := glob.MustCompile(allowGlob); g.Match(artifactFile.Path) {
				ignoreArtifact = true
				dl.Info(&checker.LogMessage{Text: fmt.Sprintf(
					"ignoring binary artifact at %s due to ignored glob path %s",
					artifactFile.Path,
					g,
				)})
			}
		}

		if !ignoreArtifact {
			dl.Info(&checker.LogMessage{
				Path: artifactFile.Path, Type: checker.FileTypeBinary,
				Offset: artifactFile.Offset,
				Text:   "binary detected",
			})
			return Fail, nil
		}
	}

	dl.Info(&checker.LogMessage{Text: "repo was free of binary artifacts"})
	return Pass, nil
}

func CheckNoVulnerabilities(results *checker.RawResults, dl checker.DetailLogger) (PolicyResult, error) {
	nVulns := len(results.VulnerabilitiesResults.Vulnerabilities)

	dl.Info(&checker.LogMessage{Text: fmt.Sprintf("found %d vulnerabilities in package", nVulns)})

	return nVulns == 0, nil
}

func toString(cs checker.Changeset) string {
	platform := cs.ReviewPlatform
	if platform == "" {
		platform = "unknown"
	}
	return fmt.Sprintf("%s(%s)", platform, cs.RevisionID)
}

func CheckCodeReviewed(
	reqs CodeReviewRequirements,
	results *checker.RawResults,
	dl checker.DetailLogger,
) (PolicyResult, error) {
	for _, changeset := range results.CodeReviewResults.DefaultBranchChangesets {
		numApprovers := 0
		approvers := make(map[string]bool)
		// CodeReview check is limited to github.com pull request reviews
		// Log if a change isn't a github pr since it's a bit unintuitive
		foundLinkedReviews := false

		for _, appr := range reqs.RequiredApprovers {
			// Required approvers must approve, other approvals optional
			approvers[appr] = false
		}

		for i := range changeset.Commits {
			commit := changeset.Commits[i]
			for _, review := range commit.AssociatedMergeRequest.Reviews {
				foundLinkedReviews = true
				if review.State == "APPROVED" {
					numApprovers += 1
					approvers[review.Author.Login] = true
				}
			}
		}

		if !foundLinkedReviews {
			dl.Warn(
				&checker.LogMessage{
					Text: fmt.Sprintf(
						"no code reviews linked to %s",
						toString(changeset),
					),
				},
			)
		}

		if numApprovers < reqs.MinReviewers {
			dl.Info(
				&checker.LogMessage{
					Text: fmt.Sprintf(
						"not enough approvals for %s (needed:%d found:%d)",
						toString(changeset),
						reqs.MinReviewers,
						numApprovers,
					),
				},
			)
			return Fail, nil
		}

		missingApprovers := false
		for appr, present := range approvers {
			missingApprovers = missingApprovers || (!present)
			if !present {
				dl.Info(
					&checker.LogMessage{
						Text: fmt.Sprintf(
							"approver %s required but didn't approve %s",
							appr,
							toString(changeset),
						),
					},
				)
			}
		}

		if missingApprovers {
			return Fail, nil
		}
	}

	return Pass, nil
}

func CheckNoUnpinnedDependencies(
	allowed []Dependency,
	results *checker.RawResults,
	dl checker.DetailLogger,
) (PolicyResult, error) {
	for i := range results.PinningDependenciesResults.Dependencies {
		dep := results.PinningDependenciesResults.Dependencies[i]
		if (dep.PinnedAt == nil || *dep.PinnedAt == "") && !isUnpinnedDependencyAllowed(dep, allowed) {
			dl.Info(&checker.LogMessage{Text: fmt.Sprintf("found unpinned dependency %v", dep)})
			return Fail, nil
		}
	}

	dl.Info(&checker.LogMessage{Text: "repo was free of unpinned dependencies"})
	return Pass, nil
}

func isUnpinnedDependencyAllowed(d checker.Dependency, allowed []Dependency) bool {
	for i := range allowed {
		a := allowed[i]
		if *d.Name == a.PackageName {
			return true
		}
		if d.Location != nil && strings.HasPrefix(d.Location.Path, a.Filepath) {
			return true
		}
	}
	return false
}

// ParseFromFile takes a policy file and returns an AttestationPolicy.
func ParseAttestationPolicyFromFile(policyFile string) (*AttestationPolicy, error) {
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return nil, sce.WithMessage(sce.ErrScorecardInternal,
				fmt.Sprintf("os.ReadFile: %v", err))
		}

		ap, err := ParseAttestationPolicyFromYAML(data)
		if err != nil {
			return nil,
				sce.WithMessage(
					sce.ErrScorecardInternal,
					fmt.Sprintf("spol.ParseFromYAML: %v", err),
				)
		}

		return ap, nil
	}

	return nil, nil
}

// Parses a policy file and returns a AttestationPolicy.
func ParseAttestationPolicyFromYAML(b []byte) (*AttestationPolicy, error) {
	ap := AttestationPolicy{}

	err := yaml.Unmarshal(b, &ap)
	if err != nil {
		return &ap, sce.WithMessage(sce.ErrScorecardInternal, err.Error())
	}

	return &ap, nil
}
