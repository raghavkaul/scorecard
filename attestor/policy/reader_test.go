// Copyright 2022 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package policy

import (
	"testing"
)

func TestParseURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri    string
		bucket string
		object string
		err    bool
	}{
		{
			uri: "",
			err: true,
		},
		{
			uri: "gs:/",
			err: true,
		},
		{
			uri:    "gs://a/b/c/d/",
			bucket: "a",
			object: "b/c/d/",
			err:    false,
		},
		{
			uri:    "gs://scorecard-binauthz-test/policy-binauthz.yaml",
			bucket: "scorecard-binauthz-test",
			object: "policy-binauthz.yaml",
			err:    false,
		},
	}

	for i := range tests {
		tt := &tests[i]

		gcs := IsGCSUri(tt.uri)
		if !gcs != tt.err {
			t.Fatalf("gcs uri %s expected error %v isGCS %v", tt.uri, tt.err, gcs)
		}

		b, err := parseURI(tt.uri)

		if tt.err != (err != nil) {
			t.Fatalf("gcs uri %s expected error %v got error %s", tt.uri, tt.err, err)
		}

		if b.bucket != tt.bucket || b.object != tt.object {
			t.Fatalf(
				"gcs uri %s expected bucket %s object %s got bucket %s object %s",
				tt.uri, tt.bucket, tt.object, b.bucket, b.object,
			)
		}
	}
}
