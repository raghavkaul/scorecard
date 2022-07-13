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

package evaluation

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/clients"
)

// Review levels. Allows us to grant 'partial credit' for Code Review
const (
	NoReview             int = 0 // Changes were not reviewed before merging
	SomeReview               = 0 // Changes were reviewed
	Approval                 = 1 // Some portion of the revisions in this set of changes were approved by someone
	SupercedingApproval      = 2 // The final revision in this set of changes was approved by someone
	ApprovedByMaintainer     = 3 // The final revision in this set of changes was approved by a contributor with write access
)

func CodeReview2(name string, dl checker.DetailLogger,
	d *checker.SmartCodeReviewData, c *checker.ContributorsData,
) checker.CheckResult {
	// Look at the last w changesets
	nMerges := 0
	windowSz := 10
	pr := d.DefaultBranchPulls[0]

	totalReviewed := 0

	for i := range d.DefaultBranchPulls {
		pull := d.DefaultBranchPulls[i]

		// If a GitHub PR doesn't squash commits, all commits included
		// will point to the same PR (i.e. 'Merge Request'). For Code Review,
		// we consider the reviews on the last commit in a PR to 'supercede'
		// other reviews
		// TODO: Handle if the last commit wasn't reviewed
		isSupercedingReview := commit.AssociatedMergeRequest.Number == mr.Number

		// We want to evaluate whether all the commits associated with a set
		// of changes were reviewed, not checking them indiivdually
		// TODO: Do we need nMerges or can we just use i?
		if isSupercedingReview {
			nMerges++
		}

		// Check if the PR was 'approved' by looking at the newest review. This
		// helps address situations where changes were requested and subsequently
		// made by the author, and that PR conversations are 'resolved' by an
		// approving review
		lastReviewState := ""
		for _, r := range mr.Reviews {
			if ReviewWasByMaintainer(&r, c) {
				if r.State == "APPROVED" || r.State == "REQUEST_CHANGES" {
					lastReviewState = r.State
				}
			}
		}

		// If the last review before a PR is merged requested changes, the maintainer
		// may have ignored those reviews to merge
		// TODO: Handle the else case
		if lastReviewState == "APPROVED" {
			totalReviewed++
		}

		if isSupercedingReview {
		} else {
		}

		if nMerges >= windowSz {
			break
		}

		mr = commit.AssociatedMergeRequest
	}

	return checker.CreateProportionalScoreResult(name, reason, nbReviews, totalCommits)
}

// Ensure that a pull request was reviewed by a maintainer to that repo
// In this case, we define 'maintainer' loosely to mean 'this individual
// has write access'.
// TODO: Make reviews by more recognized contributors worth more
func ReviewWasByMaintainer(r *clients.Review, c *checker.ContributorsData) bool {
	for _, contributor := range c.Contributors {
		if contributor.User.Login == r.Author.Login {
			return contributor.IsWriter
		}

	}

	return false
}
