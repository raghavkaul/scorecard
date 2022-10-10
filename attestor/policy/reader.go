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
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"cloud.google.com/go/storage"
)

func IsGCSUri(uri string) bool {
	return strings.HasPrefix(uri, "gs://")
}

type BucketInfo struct {
	bucket string
	object string
}

type InvalidBucketURIError struct {
	URI string
}

func (ep InvalidBucketURIError) Error() string {
	return fmt.Sprintf("invalid bucket uri %s, expected gs://<bucket-name>/<path/to/object>", ep.URI)
}

func parseURI(uri string) (BucketInfo, error) {
	//nolint:lll
	// From https://github.com/GoogleCloudPlatform/gsutil/blob/a1c563b671966761e9f69f543d0ca91e3053010a/gslib/storage_url.py#L37
	r, err := regexp.Compile(`gs://(?P<bucket>[^/]*)/(?P<object>.*)`)
	if err != nil {
		return BucketInfo{}, fmt.Errorf("scorecard internal error %w", err)
	}

	m := r.FindStringSubmatch(uri)
	if m == nil || len(m) < 3 {
		return BucketInfo{}, InvalidBucketURIError{URI: uri}
	}

	return BucketInfo{bucket: m[1], object: m[2]}, nil
}

func FetchPolicy(uri string) ([]byte, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't initialize cloud storage client: %w", err)
	}

	b, err := parseURI(uri)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't parse cloud storage uri: %w", err)
	}

	bkt := client.Bucket(b.bucket)
	obj := bkt.Object(b.object)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't initialize reader for cloud storage object: %w", err)
	}
	defer reader.Close()

	slurp, err := io.ReadAll(reader)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't read cloud storage object: %w", err)
	}

	return slurp, nil
}
