package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// This interface lets Scorecard look up package manager metadata for a project.
type ProjectPackageClient interface {
	GetProjectPackageVersions(ctx context.Context, host, project string) (*ProjectPackageVersions, error)
}

type depsDevClient struct {
	client *http.Client
}

type ProjectPackageVersions struct {
	// field alignment
	//nolint:govet
	Versions []struct {
		VersionKey struct {
			System  string `json:"system"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"versionKey"`
		SLSAProvenances []struct {
			SourceRepository string `json:"sourceRepository"`
			Commit           string `json:"commit"`
			Verified         bool   `json:"verified"`
		} `json:"slsaProvenances"`
		RelationType       string `json:"relationType"`
		RelationProvenance string `json:"relationProvenance"`
	} `json:"versions"`
}

func CreateDepsDevClient() ProjectPackageClient {
	return depsDevClient{
		client: &http.Client{},
	}
}

func (d depsDevClient) GetProjectPackageVersions(
	ctx context.Context, host, project string,
) (*ProjectPackageVersions, error) {
	path := fmt.Sprintf("%s/%s", host, project)
	query := fmt.Sprintf("https://api.deps.dev/v3/projects/%s:packageversions", url.QueryEscape(path))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("deps.dev GetProjectPackageVersions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("resp.Body.Read: %w", err)
	}

	var res ProjectPackageVersions
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("url: %s\n", query)
		fmt.Printf("resp: %s\n", resp.Status)
		fmt.Printf("body: %s\n", string(body))
		return nil, fmt.Errorf("json.Unmarshal from deps.dev: %w", err)
	}

	return &res, nil
}
