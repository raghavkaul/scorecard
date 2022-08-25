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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/clients"
	sce "github.com/ossf/scorecard/v4/errors"
)

const (
	reviewPlatformGitHub      = "GitHub"
	reviewPlatformProw        = "Prow"
	reviewPlatformGerrit      = "Gerrit"
	reviewPlatformPhabricator = "Phabricator"
	reviewPlatformPiper       = "Piper"
)

// CodeReview applies the score policy for the Code-Review check.
func CodeReview(name string, dl checker.DetailLogger,
	r *checker.CodeReviewData,
) checker.CheckResult {
	if r == nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, "empty raw data")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	if len(r.DefaultBranchCommits) == 0 {
		return checker.CreateInconclusiveResult(name, "no commits found")
	}

	totalReviewed := map[string]int{
		reviewPlatformGitHub:      0,
		reviewPlatformProw:        0,
		reviewPlatformGerrit:      0,
		reviewPlatformPhabricator: 0,
		reviewPlatformPiper:       0,
	}

	for i := range r.DefaultBranchCommits {
		commit := r.DefaultBranchCommits[i]

		rs := getApprovedReviewSystem(&commit, dl)
		if rs == "" {
			dl.Warn(&checker.LogMessage{
				Text: fmt.Sprintf("no reviews found for commit: %s", commit.SHA),
			})
			continue
		}

		if rs == reviewPlatformGitHub {
		}

		totalReviewed[rs]++
	}

	if totalReviewed[reviewPlatformGitHub] == 0 &&
		totalReviewed[reviewPlatformGerrit] == 0 &&
		totalReviewed[reviewPlatformProw] == 0 &&
		totalReviewed[reviewPlatformPhabricator] == 0 && totalReviewed[reviewPlatformPiper] == 0 {
		return checker.CreateMinScoreResult(name, "no reviews found")
	}

	totalCommits := len(r.DefaultBranchCommits)
	// Consider a single review system.
	nbReviews, reviewSystem := computeReviews(totalReviewed)
	if nbReviews == totalCommits {
		return checker.CreateMaxScoreResult(name,
			fmt.Sprintf("all last %v commits are reviewed through %s", totalCommits, reviewSystem))
	}

	reason := fmt.Sprintf("%s code reviews found for %v commits out of the last %v", reviewSystem, nbReviews, totalCommits)
	return checker.CreateProportionalScoreResult(name, reason, nbReviews, totalCommits)
}

func computeReviews(m map[string]int) (int, string) {
	n := 0
	s := ""
	for k, v := range m {
		if v > n {
			n = v
			s = k
		}
	}
	return n, s
}

func isBot(name string) bool {
	for _, substring := range []string{"bot", "gardener"} {
		if strings.Contains(name, substring) {
			return true
		}
	}
	return false
}

func getApprovedReviewSystem(c *clients.Commit, dl checker.DetailLogger) string {
	switch {
	case isReviewedOnGitHub(c, dl):
		return reviewPlatformGitHub
	case isReviewedOnProw(c, dl):
		return reviewPlatformProw
	case isReviewedOnGerrit(c, dl):
		return reviewPlatformGerrit
	case isReviewedOnPhabricator(c, dl):
		return reviewPlatformPhabricator
	case isReviewedOnPiper(c, dl):
		return reviewPlatformPiper
	}
	return ""
}

func isReviewedOnGitHub(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	mr := c.AssociatedMergeRequest

	return !mr.MergedAt.IsZero(), strconv.Itoa(mr.Number)

}

func isReviewedOnProw(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	if isBot(c.Committer.Login) {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("skip commit %s from bot account: %s", c.SHA, c.Committer.Login),
		})
		return true, ""
	}

	if !c.AssociatedMergeRequest.MergedAt.IsZero() {
		for _, l := range c.AssociatedMergeRequest.Labels {
			if l.Name == "lgtm" || l.Name == "approved" {
				dl.Debug(&checker.LogMessage{
					Text: fmt.Sprintf("commit %s review was through %s #%d approved merge request",
						c.SHA, reviewPlatformProw, c.AssociatedMergeRequest.Number),
				})
				return true, ""
			}
		}
	}
	return false, ""
}

func isReviewedOnGerrit(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	if isBot(c.Committer.Login) {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("skip commit %s from bot account: %s", c.SHA, c.Committer.Login),
		})
		return true, ""
	}

	m := c.Message
	if strings.Contains(m, "\nReviewed-on: ") &&
		strings.Contains(m, "\nReviewed-by: ") {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformGerrit),
		})
		return true, ""
	}
	return false, ""
}

func isReviewedOnPhabricator(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	if isBot(c.Committer.Login) {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("skip commit %s from bot account: %s", c.SHA, c.Committer.Login),
		})
		return true, ""
	}

	m := c.Message
	if strings.Contains(m, "\nDifferential Revision: ") &&
		strings.Contains(m, "\nReviewed By: ") {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformPhabricator),
		})
		// FIXME: Use regular expressions
		phabricatorDifferentialRevision := strings.SplitN(m, ":", 2)[1]
		return true, phabricatorDifferentialRevision
	}
	return false, ""
}

func isReviewedOnPiper(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	m := c.Message
	if strings.Contains(m, "\nPiperOrigin-RevId: ") {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformPiper),
		})
		// FIXME: Use regular expressions
		piperRevisionId := strings.SplitN(m, ":", 2)[1]
		return true, piperRevisionId
	}
	return false, ""
}

type Changeset struct {
	Commits        []clients.Commit
	ReviewPlatform string
	RevisionId     string
}

// Group, at maximum, N=`window` commits by the changeset they belong to
// Commits must be in-order
func getChangesets(commits []clients.Commit, window int, dl checker.DetailLogger) []Changeset {
	changesets := []Changeset{}

	if len(commits) < window {
		window = len(commits)
	}

	currentReviewPlatform, currentRevision, _ := getCommitRevisionByPlatform(&commits[0], dl)

	j := 0

	for i := 1; i < window; i++ {
		commit := commits[i]

		reviewPlatform, revision, err := getCommitRevisionByPlatform(&commit, dl)

		if err != nil || revision != currentRevision || reviewPlatform != currentReviewPlatform {
			changesets = append(changesets, Changeset{commits[j:i], reviewPlatform, currentRevision})
			// Add all previous commits to the 'batch' of a single changeset
			j = i
			currentRevision = revision
			currentReviewPlatform = reviewPlatform
		}
	}

	return changesets
}

func getCommitRevisionByPlatform(c *clients.Commit, dl checker.DetailLogger) (string, string, error) {
	foundRev, revisionId := isReviewedOnGitHub(c, dl)
	if foundRev {
		return reviewPlatformGitHub, revisionId, nil
	}

	foundRev, revisionId = isReviewedOnProw(c, dl)
	if foundRev {
		return reviewPlatformProw, revisionId, nil
	}

	foundRev, revisionId = isReviewedOnGerrit(c, dl)
	if foundRev {
		return reviewPlatformGerrit, revisionId, nil
	}

	foundRev, revisionId = isReviewedOnPhabricator(c, dl)
	if foundRev {
		return reviewPlatformPhabricator, revisionId, nil
	}

	foundRev, revisionId = isReviewedOnPiper(c, dl)
	if foundRev {
		return reviewPlatformPiper, revisionId, nil
	}

	return "", "", errors.New("")
}

type ReviewScore = int

const (
	// TODO More partial credit? E.g. approval from non-contributor, discussion liveness,
	// number of resolved comments, number of approvers (more eyes on a project) ?
	NoReview                     ReviewScore = 0 // No approving review by contributors before merge
	Reviewed                                 = 1 // Changes were reviewed by contributor w/ write access
	Approved                                 = 2 // Changes were approved by contributor w/ write access
	ApprovedAtHead                           = 3 // The HEAD revision of this changeset received an approval
	ApprovedWithCommentsResolved             = 4 // All revisions were approved and discussions were resolved
	ApprovedOutsideGithub                    = 4 // Changes were reviewed & approved outside Github. Full marks
	// since we can't look at details at those platforms yet
)

func reviewScoreForGitHub2(changesets []Changeset, c *checker.ContributorsData, dl checker.DetailLogger) float64 {
	sum := 0.0
	for _, changeset := range changesets {
		sum += float64(reviewScoreForChangeset(changeset, c))
	}

	return sum / float64(len(changesets))

}

func reviewScoreForChangeset(changeset Changeset, c *checker.ContributorsData) (score ReviewScore) {
	score = NoReview
	// A Changeset is a list of commits plus a pull request

	// List all PR comments for this Changeset
	// Get state of all PR comments
	// If any PR comments state is unresolved then comments are not resolved
	if len(changeset.Commits) <= 1 {
		// Handle
	}

	if changeset.ReviewPlatform != reviewPlatformGitHub {
		score = ApprovedOutsideGithub
		return
	}

	mr := changeset.Commits[0].AssociatedMergeRequest

	// Get the Head SHA for this Changeset
	// Get the reviews for that Head SHA
	// If there is an approving review by a contributor with write access, ApprovedAtHead
	// If comments are also all resolved, then ApprovedWithCommentsResolved
	if len(mr.Reviews) > 0 {
		score = Reviewed
	}

	for _, review := range mr.Reviews {

		if review.State == "APPROVED" {
			isContributor := false

			for _, c := range c.Contributors {
				if c.User.Login == review.Author.Login {
					isContributor = c.RepoAssociation.Gte(user.RepoAssocation.RepoAssociationContributor)
				}
			}

			if !isContributor {
				continue
			}

			score = Approved

			if review.SHA == headSHA {
				for i := range mr.Comments {
					comment := mr.Comments[i]
					if comment.State == "OPEN" {
						score = ApprovedWithCommentsResolved
						return
					}
				}
				score = ApprovedAtHead
				return
			}
		}
	}

	return
}
