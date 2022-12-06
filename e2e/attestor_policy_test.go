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

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/ossf/scorecard/v4/attestor/command"
	"github.com/ossf/scorecard/v4/attestor/policy"
	scut "github.com/ossf/scorecard/v4/utests"
)

func executeCmd(c *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	c.SetOut(buf)
	c.SetErr(buf)
	c.SetArgs(args)

	err := c.Execute()
	return strings.TrimSpace(buf.String()), err
}

var _ = Describe("E2E TEST PAT: scorecard-attestor policy", func() {
	Context("E2E TEST:Validating scorecard attestation policy", func() {
		It("Should successfully attest to repos without any errors", func() {
			tt := []struct {
				name   string
				args   []string
				policy policy.AttestationPolicy
				result scut.TestReturn
			}{
				{
					name: "test good repo",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-good",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      true,
						PreventKnownVulnerabilities: true,
						PreventUnpinnedDependencies: true,
					},
				},
				{
					name: "test bad repo with policies disabled",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      false,
						PreventKnownVulnerabilities: true,
						PreventUnpinnedDependencies: false,
					},
				},
				{
					name: "test bad repo with ignored binary artifact",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      true,
						AllowedBinaryArtifacts:      []string{"test-binary-artifact-*"},
						PreventKnownVulnerabilities: true,
						PreventUnpinnedDependencies: false,
					},
				},
				{
					name: "test bad repo with ignored dep by path",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      false,
						PreventUnpinnedDependencies: true,
						AllowedUnpinnedDependencies: []policy.Dependency{{Filepath: "Dockerfile"}},
					},
				},
				{
					name: "test bad repo with ignored dep by name",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      false,
						PreventUnpinnedDependencies: true,
						AllowedUnpinnedDependencies: []policy.Dependency{{PackageName: "static-debian11"}, {PackageName: "golang"}},
					},
				},
				{
					name: "test bad repo with everything ignored",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      true,
						AllowedBinaryArtifacts:      []string{"test-binary-artifact-*"},
						PreventKnownVulnerabilities: true,
						PreventUnpinnedDependencies: true,
						AllowedUnpinnedDependencies: []policy.Dependency{{Filepath: "Dockerfile"}},
					},
				},
			}

			for _, tc := range tt {
				fmt.Printf("attestor_policy_test.go: %s\n", tc.name)
				f, err := os.CreateTemp("/tmp", strings.ReplaceAll(tc.name, " ", "-"))
				Expect(err).Should(BeNil())
				defer os.Remove(f.Name())

				buf, err := yaml.Marshal(tc.policy)
				Expect(err).Should(BeNil())

				nbytes, err := f.Write(buf)
				Expect(err).Should(BeNil())
				Expect(nbytes).Should(BeNumerically(">", 0))

				tc.args = append(tc.args, "--policy="+f.Name())

				out, err := executeCmd(command.RootCmd, tc.args...)
				Expect(err).Should(BeNil())

				log, err := logContainingMsg(out, "image passed scorecard attestation policy check")
				Expect(err).Should(BeNil())
				Expect(log).ShouldNot(BeNil())
			}
		})

		It("Should refuse to attest to repos that don't pass policy", func() {
			tt := []struct {
				name   string
				args   []string
				policy policy.AttestationPolicy
				result scut.TestReturn
			}{
				{
					name: "test bad repo",
					args: []string{
						"verify",
						"--repo-url=https://github.com/ossf-tests/scorecard-binauthz-test-bad",
					},
					policy: policy.AttestationPolicy{
						PreventBinaryArtifacts:      true,
						PreventKnownVulnerabilities: true,
						PreventUnpinnedDependencies: true,
						EnsureCodeReviewed:          true,
					},
				},
			}

			for _, tc := range tt {
				fmt.Printf("attestor_policy_test.go: %s\n", tc.name)
				f, err := os.CreateTemp("/tmp", strings.ReplaceAll(tc.name, " ", "-"))
				Expect(err).Should(BeNil())
				defer os.Remove(f.Name())

				buf, err := yaml.Marshal(tc.policy)
				Expect(err).Should(BeNil())

				nbytes, err := f.Write(buf)
				Expect(err).Should(BeNil())
				Expect(nbytes).Should(BeNumerically(">", 0))

				tc.args = append(tc.args, "--policy="+f.Name())

				out, err := executeCmd(command.RootCmd, tc.args...)
				Expect(err).Should(BeNil())

				log, err := logContainingMsg(out, "image failed scorecard attestation policy check")
				Expect(err).Should(BeNil())
				Expect(log).ShouldNot(BeNil())
			}
		})
	})
})

func logContainingMsg(log, needle string) (string, error) {
	p, err := regexp.Compile(`time="(.+)" level=(\w+) msg="(.+)"`)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}

	for _, line := range strings.Split(log, "\n") {
		fmt.Printf("line: %v\n", line)
		matches := p.FindAllString(line, -1)
		if matches == nil || len(matches) < 4 {
			continue
		}
		logMsg := matches[3]
		if strings.Contains(logMsg, needle) {
			return logMsg, nil
		}
	}

	return "", nil
}
