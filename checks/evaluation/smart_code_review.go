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
        "fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/clients"
)

// Review levels. Allows us to grant 'partial credit' for Code Review
const (
	NoReview             int = 0 // Changes were not reviewed before merging
	UnresolvedDiscussion     = 0 // Changes were reviewed, but not approved
	Approval                 = 1 // Some revisions in this set of changes were approved by someone
	ApprovalByMaintainer     = 2 // The approver has write access, but there may be unreviewed commits
        ExternalPlatformApproval = 2 // Commit was reviewed & approved outside of GitHub
)

func SmartCodeReview(name string, dl checker.DetailLogger,
	d *checker.SmartCodeReviewData, c *checker.ContributorsData,
) checker.CheckResult {
        // TODO: Handle commits that aren't part of a changeset
        // Maybe use the %age of commits that don't have a corresponding merge as 'Unreviewed' ?
        // And use that to weight the responses?
        // Maybe treat each commit pushed directly as a 'changeset', and each PR + all the commits contained in it as a changeset (i.e. autosquash everything). 

	// Look at the last w changesets
	totalReviewed := map[string]int{
		reviewPlatformGitHub:      0,
		reviewPlatformProw:        0,
		reviewPlatformGerrit:      0,
		reviewPlatformPhabricator: 0,
		reviewPlatformPiper:       0,
	}

	for i := range d.DefaultBranchPulls {
		pull := d.DefaultBranchPulls[i]
	
                
                if isBot(pull.Author.Login) {
		    dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("skip change set %s from bot account: %s", pull.HeadSHA, pull.Author.Login),
                    })
		}

		rs := getReviewScore(&pull, c, dl)

		if rs == "" {
			dl.Warn(&checker.LogMessage{
				Text: fmt.Sprintf("no reviews found for changeset at revision: %s", pull.HeadSHA),
			})
			continue
		}

		totalReviewed[rs]++
	}

	if totalReviewed[reviewPlatformGitHub] == 0 &&
		totalReviewed[reviewPlatformGerrit] == 0 &&
		totalReviewed[reviewPlatformProw] == 0 &&
		totalReviewed[reviewPlatformPhabricator] == 0 && totalReviewed[reviewPlatformPiper] == 0 {
		return checker.CreateMinScoreResult(name, "no reviews found")
	}

	totalPulls := len(d.DefaultBranchPulls)
	// Consider a single review system.
	nbReviews, reviewSystem := computeReviews(totalReviewed)
	if nbReviews == totalPulls {
		return checker.CreateMaxScoreResult(name,
			fmt.Sprintf("all last %v changesets are reviewed through %s", totalPulls, reviewSystem))
	}

	reason := fmt.Sprintf("%s code reviews found for %v changesets out of the last %v", reviewSystem, nbReviews, totalPulls)
	return checker.CreateProportionalScoreResult(name, reason, nbReviews, totalPulls)
}



func getReviewScore(pr *clients.PullRequest, c *checker.ContributorsData, dl checker.DetailLogger) int {
	return reviewScoreForGitHub(pr, c, dl)
	// case reviewScoreForProw(pr, dl):
	// 	return reviewPlatformProw
	// case reviewScoreForGerrit(pr, dl):
	// 	return reviewPlatformGerrit
	// case reviewScoreForPhabricator(pr, dl):
	// 	return reviewPlatformPhabricator
	// case reviewScoreForPiper(pr, dl):
	// 	return reviewPlatformPiper
}

 
func reviewScoreForProw(c *clients.Commit, dl checker.DetailLogger) int {

	if !c.AssociatedMergeRequest.MergedAt.IsZero() {
		for _, l := range c.AssociatedMergeRequest.Labels {
			if l.Name == "lgtm" || l.Name == "approved" {
				dl.Debug(&checker.LogMessage{
					Text: fmt.Sprintf("commit %s review was through %s #%d approved merge request",
						c.SHA, reviewPlatformProw, c.AssociatedMergeRequest.Number),
				})
				return true
			}
		}
	}
	return false
}
// 
// func reviewScoreForGerrit(c *clients.PullRequest, dl checker.DetailLogger) int {
// 	if isBot(c.Committer.Login) {
// 		dl.Debug(&checker.LogMessage{
// 			Text: fmt.Sprintf("skip commit %s from bot account: %s", c.SHA, c.Committer.Login),
// 		})
// 		return true
// 	}
// 
// 	m := c.Message
// 	if strings.Contains(m, "\nReviewed-on: ") &&
// 		strings.Contains(m, "\nReviewed-by: ") {
// 		dl.Debug(&checker.LogMessage{
// 			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformGerrit),
// 		})
// 		return true
// 	}
// 	return false
// }
// 
// func reviewScoreForPhabricator(c *clients.PullRequest, dl checker.DetailLogger) int {
// 	if isBot(c.Committer.Login) {
// 		dl.Debug(&checker.LogMessage{
// 			Text: fmt.Sprintf("skip commit %s from bot account: %s", c.SHA, c.Committer.Login),
// 		})
// 		return true
// 	}
// 
// 	m := c.Message
// 	if strings.Contains(m, "\nDifferential Revision: ") &&
// 		strings.Contains(m, "\nReviewed By: ") {
// 		dl.Debug(&checker.LogMessage{
// 			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformPhabricator),
// 		})
// 		return true
// 	}
// 	return false
// }
// 
// func reviewScoreForPiper(c *clients.PullRequest, dl checker.DetailLogger) int {
// 	m := c.Message
// 	if strings.Contains(m, "\nPiperOrigin-RevId: ") {
// 		dl.Debug(&checker.LogMessage{
// 			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformPiper),
// 		})
// 		return true
// 	}
// 	return false
// }
// 
