package provider

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceDockerRegistryImage() *schema.Resource {
	return &schema.Resource{
		Description: "Reads the image metadata from a Docker Registry. " +
			"Used in conjunction with the [docker_image](../resources/image.md) resource to keep an " +
			"image up to date on the latest available version of the tag.",

		ReadContext: dataSourceDockerRegistryImageRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "The name of the Docker image, including any tags. e.g. `alpine:latest`",
				Required:    true,
			},

			"sha256_digest": {
				Type:        schema.TypeString,
				Description: "The content digest of the image, as stored in the registry.",
				Computed:    true,
			},

			"insecure_skip_verify": {
				Type: schema.TypeBool,
				Description: "If `true`, the verification of TLS certificates of the server/registry is disabled. " +
					"Defaults to `false`",
				Optional: true,
				Default:  false,
			},
		},
	}
}

func dataSourceDockerRegistryImageRead(_ context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	pullOpts := parseImageOptions(d.Get("name").(string))

	authConfig, err := getAuthConfigForRegistry(pullOpts.Registry, meta.(*ProviderConfig))
	if err != nil {
		// The user did not provide a credential for this registry.
		// But there are many registries where you can pull without a credential.
		// We are setting default values for the authConfig here.
		authConfig.Username = ""
		authConfig.Password = ""
		authConfig.ServerAddress = "https://" + pullOpts.Registry
	}

	insecureSkipVerify := d.Get("insecure_skip_verify").(bool)
	digest, err := getImageDigest(pullOpts.Registry, authConfig.ServerAddress, pullOpts.Repository, pullOpts.Tag,
		authConfig.Username, authConfig.Password, insecureSkipVerify, false)
	if err != nil {
		digest, err = getImageDigest(pullOpts.Registry, authConfig.ServerAddress, pullOpts.Repository, pullOpts.Tag,
			authConfig.Username, authConfig.Password, insecureSkipVerify, true)
		if err != nil {
			return diag.Errorf("Got error when attempting to fetch image version %s:%s from registry: %s",
				pullOpts.Repository, pullOpts.Tag, err)
		}
	}

	d.SetId(digest)
	_ = d.Set("sha256_digest", digest)

	return nil
}

func getImageDigest(registry string, registryWithProtocol string, image, tag, username, password string,
	insecureSkipVerify, fallback bool) (string, error) {
	client := buildHttpClientForRegistry(registryWithProtocol, insecureSkipVerify)

	ctx := context.TODO()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		registryWithProtocol+"/v2/"+image+"/manifests/"+tag, nil)
	if err != nil {
		return "", fmt.Errorf("error creating registry request: %s", err.Error())
	}

	if username != "" {
		if registry != "ghcr.io" && !isECRRepositoryURL(registry) &&
			!isAzureCRRepositoryURL(registry) && registry != "gcr.io" {
			req.SetBasicAuth(username, password)
		} else {
			if isECRRepositoryURL(registry) {
				password = normalizeECRPasswordForHTTPUsage(password)
				req.Header.Add("Authorization", "Basic "+password)
			} else {
				req.Header.Add("Authorization", "Bearer "+b64.StdEncoding.EncodeToString([]byte(password)))
			}
		}
	}

	setupHTTPHeadersForRegistryRequests(req, fallback)

	if req.Body != nil {
		defer req.Body.Close()
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error during registry request: %s", err.Error())
	}

	defer resp.Body.Close()
	switch resp.StatusCode {
	// Basic auth was valid or not needed
	case http.StatusOK:
		return getDigestFromResponse(resp)

	// Either OAuth is required or the basic auth creds were invalid
	case http.StatusUnauthorized:
		if !strings.HasPrefix(resp.Header.Get("www-authenticate"), "Bearer") {
			return "", fmt.Errorf("bad credentials: %s", resp.Status)
		}

		token, err := getAuthToken(resp.Header.Get("www-authenticate"),
			username, password, client)
		if err != nil {
			return "", err
		}

		req.Header.Set("Authorization", "Bearer "+token)

		// Do a HEAD request to docker registry first (avoiding Docker Hub rate limiting)
		digestResponse, err := doDigestRequest(req, client)
		if err != nil {
			return "", err
		}

		digest, err := getDigestFromResponse(digestResponse)
		if err == nil {
			return digest, nil
		}

		// If previous HEAD request does not contain required info, do a GET request
		req.Method = "GET"
		digestResponse, err = doDigestRequest(req, client)

		if err != nil {
			return "", err
		}

		return getDigestFromResponse(digestResponse)

	// Some unexpected status was given, return an error
	default:
		return "", fmt.Errorf("got bad response from registry: %s", resp.Status)
	}
}

type TokenResponse struct {
	Token       string
	AccessToken string `json:"access_token"`
}

// Parses key/value pairs from a WWW-Authenticate header.
func parseAuthHeader(header string) map[string]string {
	parts := strings.SplitN(header, " ", 2)
	parts = regexp.MustCompile(`\w+=".*?"|\w+[^\s"]+?`).FindAllString(parts[1], -1) // expression to match auth headers.
	opts := make(map[string]string)

	for _, part := range parts {
		vals := strings.SplitN(part, "=", 2)
		key := vals[0]
		val := strings.Trim(vals[1], "\", ")
		opts[key] = val
	}

	return opts
}

func getDigestFromResponse(response *http.Response) (string, error) {
	header := response.Header.Get("Docker-Content-Digest")

	if header == "" {
		body, err := io.ReadAll(response.Body)
		if err != nil || len(body) == 0 {
			return "", fmt.Errorf("error reading registry response body: %s", err.Error())
		}

		return fmt.Sprintf("sha256:%x", sha256.Sum256(body)), nil
	}

	return header, nil
}

func getAuthToken(authHeader string, username string, password string, client *http.Client) (string, error) {
	auth := parseAuthHeader(authHeader)
	params := url.Values{}
	params.Set("service", auth["service"])
	params.Set("scope", auth["scope"])
	ctx := context.TODO()
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodGet,
		auth["realm"]+"?"+params.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating registry request: %s", err.Error())
	}

	if username != "" {
		tokenRequest.SetBasicAuth(username, password)
	}

	if tokenRequest.Body != nil {
		defer tokenRequest.Body.Close()
	}

	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		return "", fmt.Errorf("error during registry request: %s", err.Error())
	}

	if tokenRequest.Body != nil {
		defer tokenRequest.Body.Close()
	}

	if tokenResponse.StatusCode != http.StatusOK {
		return "", fmt.Errorf("got bad response from registry: %s", tokenResponse.Status)
	}

	body, err := io.ReadAll(tokenResponse.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %s", err.Error())
	}

	token := &TokenResponse{}
	err = json.Unmarshal(body, token)
	if err != nil {
		return "", fmt.Errorf("error parsing OAuth token response: %s", err.Error())
	}

	if token.Token != "" {
		return token.Token, nil
	}

	if token.AccessToken != "" {
		return token.AccessToken, nil
	}

	return "", errors.New("error unsupported OAuth response")
}

func doDigestRequest(req *http.Request, client *http.Client) (*http.Response, error) {
	digestResponse, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error during registry request: %s", err.Error())
	}

	if digestResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got bad response from registry: %s", digestResponse.Status)
	}

	return digestResponse, nil
}
