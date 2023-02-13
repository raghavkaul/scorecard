// Copyright 2021 OpenSSF Scorecard Authors
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

package e2e

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks"
	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/clients/githubrepo"
	"github.com/ossf/scorecard/v4/clients/gitlabrepo"
	scut "github.com/ossf/scorecard/v4/utests"
)

var _ = Describe("E2E TEST:"+checks.CheckCITests, func() {
	Context("E2E TEST:Validating use of CI tests", func() {
		It("Should return use of CI tests", func() {
			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/airflow")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         checker.InconclusiveResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			}
			result := checks.CITests(&req)
			Expect(scut.ValidateTestReturn(nil, "CI tests run", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should return use of CI tests at commit", func() {
			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/airflow")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, "0a6850647e531b08f68118ff8ca20577a5b4062c", 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         checker.InconclusiveResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			}
			result := checks.CITests(&req)
			Expect(scut.ValidateTestReturn(nil, "CI tests run", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should return absence of CI tests in a repo with unsquashed merges", func() {
			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("duo-labs/parliament")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, "1ead655ec85bdbe0739e4a4125ce36eb48a329bc", 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 12,
			}
			result := checks.CITests(&req)
			Expect(scut.ValidateTestReturn(nil, "CI tests run", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should return use of CI tests - GitLab", func() {
			dl := scut.TestDetailLogger{}
			// Project url is gitlab.com/gitlab-org/gitlab
			repo, err := gitlabrepo.MakeGitlabRepo("gitlab.com/gitlab-org/278964")
			Expect(err).Should(BeNil())
			repoClient, err := gitlabrepo.CreateGitlabClientWithToken(context.Background(), os.Getenv("GITLAB_AUTH_TOKEN"), repo)
			Expect(err).Should(BeNil())
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 14,
			}
			expected2 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 15,
			}
			expected3 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 16,
			}
			expected4 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 17,
			}
			result := checks.CITests(&req)
			res1 := scut.ValidateTestReturn(nil, "CI tests run", &expected, &result, &dl)
			res2 := scut.ValidateTestReturn(nil, "CI tests run", &expected2, &result, &dl)
			res3 := scut.ValidateTestReturn(nil, "CI tests run", &expected3, &result, &dl)
			res4 := scut.ValidateTestReturn(nil, "CI tests run", &expected4, &result, &dl)
			Expect(res1 || res2 || res3 || res4).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should return use of CI tests at commit - GitLab", func() {
			dl := scut.TestDetailLogger{}
			// Project url is gitlab.com/gitlab-org/gitlab
			repo, err := gitlabrepo.MakeGitlabRepo("gitlab.com/gitlab-org/278964")
			Expect(err).Should(BeNil())
			repoClient, err := gitlabrepo.CreateGitlabClientWithToken(context.Background(), os.Getenv("GITLAB_AUTH_TOKEN"), repo)
			Expect(err).Should(BeNil())
			// url to commit is https://gitlab.com/gitlab-org/gitlab/-/commit/8ae23fa220d73fa07501aabd94214c9e83fe61a0
			err = repoClient.InitRepo(repo, "8ae23fa220d73fa07501aabd94214c9e83fe61a0", 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 14,
			}
			expected2 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 15,
			}
			expected3 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 16,
			}
			expected4 := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 17,
			}
			result := checks.CITests(&req)
			res1 := scut.ValidateTestReturn(nil, "CI tests run", &expected, &result, &dl)
			res2 := scut.ValidateTestReturn(nil, "CI tests run", &expected2, &result, &dl)
			res3 := scut.ValidateTestReturn(nil, "CI tests run", &expected3, &result, &dl)
			res4 := scut.ValidateTestReturn(nil, "CI tests run", &expected4, &result, &dl)
			Expect(res1 || res2 || res3 || res4).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
	})
})
