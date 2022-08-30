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
	"regexp"
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
	r *checker.CodeReviewData, c *checker.ContributorsData,
) checker.CheckResult {
	if r == nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, "empty raw data")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	if len(r.DefaultBranchCommits) == 0 {
		return checker.CreateInconclusiveResult(name, "no commits found")
	}

	changesets := getChangesets(r.DefaultBranchCommits, dl)

	score := 0
	numReviewed := 0
	for _, changeset := range changesets {
		score += reviewScoreForChangeset(changeset, c)
		if score >= Reviewed {
			numReviewed += 1
		}
	}
	reason := fmt.Sprintf("%v out of last %v changesets were reviewed before merge", numReviewed, len(changesets))

	return checker.CreateProportionalScoreResult(name, reason, score, len(changesets))
}

func isBot(name string) bool {
	for _, substring := range []string{"bot", "gardener"} {
		if strings.Contains(name, substring) {
			return true
		}
	}
	return false
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

// Given m, a commit message, find the Phabricator revision ID in it
func getPhabricatorRevId(m string) (string, error) {
	matchPhabricatorRevId, err := regexp.Compile("^Differential Revision:\\s*(\\w+)\\s+")

	if err != nil {
		return "", err
	}

	match := matchPhabricatorRevId.FindStringSubmatch(m)

	if match == nil || len(match) < 2 {
		return "", errors.New("coudn't find phabricator differential revision ID")
	}

	return match[1], nil
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
			Text: fmt.Sprintf(
				"commit %s was approved through %s",
				c.SHA,
				reviewPlatformPhabricator,
			),
		})

		revId, err := getPhabricatorRevId(m)

		if err != nil {
			dl.Debug(&checker.LogMessage{
				Text: fmt.Sprintf(
					"couldn't find phab differential revision in commit message for commit=%s",
					c.SHA,
				),
			})
		}

		return true, revId
	}
	return false, ""
}

// Given m, a commit message, find the piper revision ID in it
func getPiperRevId(m string) (string, error) {
	matchPiperRevId, err := regexp.Compile(".PiperOrigin-RevId\\s+:\\s*(\\d{3,})\\s+")

	if err != nil {
		return "", err
	}

	match := matchPiperRevId.FindStringSubmatch(m)

	if match == nil || len(match) < 2 {
		return "", errors.New("coudn't find piper revision ID")
	}

	return match[1], nil
}

func isReviewedOnPiper(c *clients.Commit, dl checker.DetailLogger) (bool, string) {
	m := c.Message
	if strings.Contains(m, "\nPiperOrigin-RevId: ") {
		dl.Debug(&checker.LogMessage{
			Text: fmt.Sprintf("commit %s was approved through %s", c.SHA, reviewPlatformPiper),
		})

		revId, err := getPiperRevId(m)

		if err != nil {
			dl.Debug(&checker.LogMessage{
				Text: fmt.Sprintf(
					"couldn't find piper revision in commit message for commit=%s",
					c.SHA,
				),
			})
		}

		return true, revId
	}
	return false, ""
}

type Changeset struct {
	Commits        []clients.Commit
	ReviewPlatform string
	RevisionId     string
}

// Group commits by the changeset they belong to
// Commits must be in-order
func getChangesets(commits []clients.Commit, dl checker.DetailLogger) []Changeset {
	changesets := []Changeset{}

	if len(commits) == 0 {
		return changesets
	}

	currentReviewPlatform, currentRevision, err := getCommitRevisionByPlatform(
		&commits[0],
		dl,
	)

	if err != nil {
		dl.Debug(&checker.LogMessage{Text: err.Error()})
		changesets = append(
			changesets,
			Changeset{commits[0:1], currentReviewPlatform, currentRevision},
		)
	}

	j := 0
	for i := 0; i < len(commits); i++ {
		if i == len(commits)-1 {
			changesets = append(
				changesets,
				Changeset{commits[j:i], currentReviewPlatform, currentRevision},
			)
			break
		}

		nextReviewPlatform, nextRevision, err := getCommitRevisionByPlatform(&commits[i+1], dl)
		if err != nil || nextReviewPlatform != currentReviewPlatform ||
			nextRevision != currentRevision {
			if err != nil {
				dl.Debug(&checker.LogMessage{Text: err.Error()})
			}
			// Add all previous commits to the 'batch' of a single changeset
			changesets = append(
				changesets,
				Changeset{commits[j:i], currentReviewPlatform, currentRevision},
			)
			currentReviewPlatform = nextReviewPlatform
			currentRevision = nextRevision
			j = i + 1
		}
	}

	return changesets
}

func getCommitRevisionByPlatform(
	c *clients.Commit,
	dl checker.DetailLogger,
) (string, string, error) {
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

	return "", "", errors.New(
		fmt.Sprintf("couldn't find linked review platform for commit %s", c.SHA),
	)
}

type ReviewScore = int

// TODO More partial credit? E.g. approval from non-contributor, discussion liveness,
// number of resolved comments, number of approvers (more eyes on a project)
const (
	NoReview                     ReviewScore = 0 // No approving review by contributors before merge
	Reviewed                                 = 1 // Changes were reviewed by contributor w/ write access
	Approved                                 = 2 // Changes were approved by contributor w/ write access
	ApprovedAtHead                           = 3 // The HEAD revision of this changeset received an approval
	ApprovedWithCommentsResolved             = 4 // All revisions were approved and discussions were resolved
	ApprovedOutsideGithub                    = 4 // Full marks until we can check review platforms outside of GitHub
)

func reviewScoreForChangeset(changeset Changeset, c *checker.ContributorsData) (score ReviewScore) {
	score = NoReview

	if changeset.ReviewPlatform != reviewPlatformGitHub {
		score = ApprovedOutsideGithub
		return
	}
	mr := changeset.Commits[0].AssociatedMergeRequest

	// A Changeset is a list of commits plus a pull request
	// List all PR comments for this Changeset
	// Get state of all PR comments
	// If any PR comments state is unresolved then comments are not resolved
	// Get the Head SHA for this Changeset
	// Get the reviews for that Head SHA
	// If there is an approving review by a contributor with write access, ApprovedAtHead
	// If comments are also all resolved, then ApprovedWithCommentsResolved
	if len(mr.Reviews) > 0 {
		score = Reviewed
	}

	for _, review := range mr.Reviews {
		if review.State == "APPROVED" {
			if !isContributor(review.Author.Login, c) {
				continue
			}
			score = Approved
			if review.SHA == mr.HeadSHA {
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

func isContributor(username string, c *checker.ContributorsData) (isContributor bool) {
	isContributor = false
	for _, c := range c.Contributors {
		if c.User.Login == username {
			isContributor = c.RepoAssociation.Gte(clients.RepoAssociationContributor)
			return
		}
	}
	return
}
