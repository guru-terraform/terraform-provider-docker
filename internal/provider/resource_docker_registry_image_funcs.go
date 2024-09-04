package provider

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDockerRegistryImageCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	cli := meta.(*ProviderConfig).DockerClient
	providerConfig := meta.(*ProviderConfig)
	name := d.Get("name").(string)
	log.Printf("[DEBUG] Creating docker image %s", name)

	pushOpts := createPushImageOptions(name)

	authConfig, err := getAuthConfigForRegistry(pushOpts.Registry, providerConfig)
	if err != nil {
		return diag.Errorf("resourceDockerRegistryImageCreate: Unable to get authConfig for registry: %s", err)
	}
	if err = pushDockerRegistryImage(ctx, cli, pushOpts, authConfig.Username, authConfig.Password); err != nil {
		return diag.Errorf("Error pushing docker image: %s", err)
	}

	insecureSkipVerify := d.Get("insecure_skip_verify").(bool)
	digest, err := getImageDigestWithFallback(pushOpts, authConfig.ServerAddress,
		authConfig.Username, authConfig.Password, insecureSkipVerify)
	if err != nil {
		return diag.Errorf("Unable to create image, image not found: %s", err)
	}
	d.SetId(digest)
	_ = d.Set("sha256_digest", digest)

	return nil
}

func resourceDockerRegistryImageRead(_ context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	providerConfig := meta.(*ProviderConfig)
	name := d.Get("name").(string)
	pushOpts := createPushImageOptions(name)
	authConfig, err := getAuthConfigForRegistry(pushOpts.Registry, providerConfig)
	if err != nil {
		return diag.Errorf("resourceDockerRegistryImageRead: Unable to get authConfig for registry: %s", err)
	}

	insecureSkipVerify := d.Get("insecure_skip_verify").(bool)
	digest, err := getImageDigestWithFallback(pushOpts, authConfig.ServerAddress,
		authConfig.Username, authConfig.Password, insecureSkipVerify)
	if err != nil {
		log.Printf("Got error getting registry image digest: %s", err)
		d.SetId("")
		return nil
	}
	_ = d.Set("sha256_digest", digest)

	return nil
}

func resourceDockerRegistryImageDelete(_ context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if d.Get("keep_remotely").(bool) {
		return nil
	}
	providerConfig := meta.(*ProviderConfig)
	name := d.Get("name").(string)
	pushOpts := createPushImageOptions(name)
	authConfig, err := getAuthConfigForRegistry(pushOpts.Registry, providerConfig)
	if err != nil {
		return diag.Errorf("resourceDockerRegistryImageDelete: Unable to get authConfig for registry: %s", err)
	}

	digest := d.Get("sha256_digest").(string)
	err = deleteDockerRegistryImage(pushOpts, authConfig.ServerAddress, digest,
		authConfig.Username, authConfig.Password, true, false)
	if err != nil {
		err = deleteDockerRegistryImage(pushOpts, authConfig.ServerAddress, pushOpts.Tag,
			authConfig.Username, authConfig.Password, true, true)
		if err != nil {
			return diag.Errorf("Got error deleting registry image: %s", err)
		}
	}

	return nil
}

func resourceDockerRegistryImageUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	return resourceDockerRegistryImageRead(ctx, d, meta)
}

// Helpers.
type internalPushImageOptions struct {
	Name               string
	FqName             string
	Registry           string
	NormalizedRegistry string
	Repository         string
	Tag                string
}

func createImageBuildOptions(buildOptions map[string]any) types.ImageBuildOptions {
	mapOfInterfacesToMapOfStrings := func(mapOfInterfaces map[string]any) map[string]string {
		mapOfStrings := make(map[string]string, len(mapOfInterfaces))
		for k, v := range mapOfInterfaces {
			mapOfStrings[k] = fmt.Sprintf("%v", v)
		}
		return mapOfStrings
	}

	interfaceArrayToStringArray := func(interfaceArray []any) []string {
		stringArray := make([]string, len(interfaceArray))
		for i, v := range interfaceArray {
			stringArray[i] = fmt.Sprintf("%v", v)
		}
		return stringArray
	}

	mapToBuildArgs := func(buildArgsOptions map[string]any) map[string]*string {
		buildArgs := make(map[string]*string, len(buildArgsOptions))
		for k, v := range buildArgsOptions {
			value := v.(string)
			buildArgs[k] = &value
		}
		return buildArgs
	}

	readULimits := func(options []any) []*units.Ulimit {
		ulimits := make([]*units.Ulimit, len(options))
		for i, v := range options {
			ulimitOption := v.(map[string]any)
			ulimit := units.Ulimit{
				Name: ulimitOption["name"].(string),
				Hard: int64(ulimitOption["hard"].(int)),
				Soft: int64(ulimitOption["soft"].(int)),
			}
			ulimits[i] = &ulimit
		}
		return ulimits
	}

	readAuthConfigs := func(options []any) map[string]registry.AuthConfig {
		authConfigs := make(map[string]registry.AuthConfig, len(options))
		for _, v := range options {
			authOptions := v.(map[string]any)
			auth := registry.AuthConfig{
				Username:      authOptions["user_name"].(string),
				Password:      authOptions["password"].(string),
				Auth:          authOptions["auth"].(string),
				Email:         authOptions["email"].(string),
				ServerAddress: authOptions["server_address"].(string),
				IdentityToken: authOptions["identity_token"].(string),
				RegistryToken: authOptions["registry_token"].(string),
			}
			authConfigs[authOptions["host_name"].(string)] = auth
		}
		return authConfigs
	}

	buildImageOptions := types.ImageBuildOptions{}
	buildImageOptions.SuppressOutput = buildOptions["suppress_output"].(bool)
	buildImageOptions.RemoteContext = buildOptions["remote_context"].(string)
	buildImageOptions.NoCache = buildOptions["no_cache"].(bool)
	buildImageOptions.Remove = buildOptions["remove"].(bool)
	buildImageOptions.ForceRemove = buildOptions["force_remove"].(bool)
	buildImageOptions.PullParent = buildOptions["pull_parent"].(bool)
	buildImageOptions.Isolation = container.Isolation(buildOptions["isolation"].(string))
	buildImageOptions.CPUSetCPUs = buildOptions["cpu_set_cpus"].(string)
	buildImageOptions.CPUSetMems = buildOptions["cpu_set_mems"].(string)
	buildImageOptions.CPUShares = int64(buildOptions["cpu_shares"].(int))
	buildImageOptions.CPUQuota = int64(buildOptions["cpu_quota"].(int))
	buildImageOptions.CPUPeriod = int64(buildOptions["cpu_period"].(int))
	buildImageOptions.Memory = int64(buildOptions["memory"].(int))
	buildImageOptions.MemorySwap = int64(buildOptions["memory_swap"].(int))
	buildImageOptions.CgroupParent = buildOptions["cgroup_parent"].(string)
	buildImageOptions.NetworkMode = buildOptions["network_mode"].(string)
	buildImageOptions.ShmSize = int64(buildOptions["shm_size"].(int))
	buildImageOptions.Dockerfile = buildOptions["dockerfile"].(string)
	buildImageOptions.Ulimits = readULimits(buildOptions["ulimit"].([]any))
	buildImageOptions.BuildArgs = mapToBuildArgs(buildOptions["build_args"].(map[string]any))
	buildImageOptions.AuthConfigs = readAuthConfigs(buildOptions["auth_config"].([]any))
	buildImageOptions.Labels = mapOfInterfacesToMapOfStrings(buildOptions["labels"].(map[string]any))
	buildImageOptions.Squash = buildOptions["squash"].(bool)
	buildImageOptions.CacheFrom = interfaceArrayToStringArray(buildOptions["cache_from"].([]any))
	buildImageOptions.SecurityOpt = interfaceArrayToStringArray(buildOptions["security_opt"].([]any))
	buildImageOptions.ExtraHosts = interfaceArrayToStringArray(buildOptions["extra_hosts"].([]any))
	buildImageOptions.Target = buildOptions["target"].(string)
	buildImageOptions.SessionID = buildOptions["session_id"].(string)
	buildImageOptions.Platform = buildOptions["platform"].(string)
	buildImageOptions.Version = types.BuilderVersion(buildOptions["version"].(string))
	buildImageOptions.BuildID = buildOptions["build_id"].(string)
	// outputs

	return buildImageOptions
}

func pushDockerRegistryImage(ctx context.Context, client *client.Client, pushOpts internalPushImageOptions,
	username, password string) error {
	pushOptions := image.PushOptions{}
	if username != "" {
		auth := registry.AuthConfig{Username: username, Password: password}
		authBytes, err := json.Marshal(auth)
		if err != nil {
			return fmt.Errorf("error creating push options: %s", err)
		}
		authBase64 := base64.URLEncoding.EncodeToString(authBytes)
		pushOptions.RegistryAuth = authBase64
	}

	out, err := client.ImagePush(ctx, pushOpts.FqName, pushOptions)
	if err != nil {
		return err
	}
	defer out.Close()

	type ErrorMessage struct {
		Error string
	}
	var errorMessage ErrorMessage
	buffIOReader := bufio.NewReader(out)
	for {
		streamBytes, err := buffIOReader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err = json.Unmarshal(streamBytes, &errorMessage); err != nil {
			return err
		}
		if errorMessage.Error != "" {
			return fmt.Errorf("error pushing image: %s", errorMessage.Error)
		}
	}

	log.Printf("[DEBUG] Pushed image: %s", pushOpts.FqName)
	return nil
}

func getAuthConfigForRegistry(
	registryWithoutProtocol string,
	providerConfig *ProviderConfig) (registry.AuthConfig, error) {
	if authConfig, ok := providerConfig.AuthConfigs.Configs[registryWithoutProtocol]; ok {
		return authConfig, nil
	}

	return registry.AuthConfig{}, fmt.Errorf("no auth config found for registry %s in auth configs: %#v",
		registryWithoutProtocol, providerConfig.AuthConfigs.Configs)
}

func buildHttpClientForRegistry(registryAddressWithProtocol string, insecureSkipVerify bool) *http.Client {
	cli := http.DefaultClient

	if strings.HasPrefix(registryAddressWithProtocol, "https://") {
		cli.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
			Proxy: http.ProxyFromEnvironment,
		}
	} else {
		cli.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}

	return cli
}

func deleteDockerRegistryImage(pushOpts internalPushImageOptions, registryWithProtocol, sha256Digest,
	username, password string, insecureSkipVerify, fallback bool) error {
	cli := buildHttpClientForRegistry(registryWithProtocol, insecureSkipVerify)

	ctx := context.TODO()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		registryWithProtocol+"/v2/"+pushOpts.Repository+"/manifests/"+sha256Digest, nil)
	if err != nil {
		return fmt.Errorf("error deleting registry image: %s", err.Error())
	}

	if username != "" {
		if pushOpts.Registry != "ghcr.io" && !isECRRepositoryURL(pushOpts.Registry) && !isAzureCRRepositoryURL(pushOpts.Registry) && pushOpts.Registry != "gcr.io" {
			req.SetBasicAuth(username, password)
		} else {
			if isECRRepositoryURL(pushOpts.Registry) {
				password = normalizeECRPasswordForHTTPUsage(password)
				req.Header.Add("Authorization", "Basic "+password)
			} else {
				req.Header.Add("Authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte(password)))
			}
		}
	}

	setupHTTPHeadersForRegistryRequests(req, fallback)

	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("error during registry request: %s", err.Error())
	}

	switch resp.StatusCode {
	// Basic auth was valid or not needed
	case http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil

	// Either OAuth is required or the basic auth creds were invalid
	case http.StatusUnauthorized:
		if !strings.HasPrefix(resp.Header.Get("www-authenticate"), "Bearer") {
			return fmt.Errorf("bad credentials: %s", resp.Status)
		}

		token, err := getAuthToken(resp.Header.Get("www-authenticate"), username, password, cli)
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", "Bearer "+token)
		defer req.Body.Close()
		oauthResp, err := cli.Do(req)
		if err != nil {
			return err
		}
		defer oauthResp.Body.Close()

		switch oauthResp.StatusCode {
		case http.StatusOK, http.StatusAccepted, http.StatusNotFound:
			return nil
		default:
			return fmt.Errorf("got bad response from registry: %s", resp.Status)
		}
		// Some unexpected status was given, return an error
	default:
		return fmt.Errorf("got bad response from registry: %s", resp.Status)
	}
}

func getImageDigestWithFallback(opts internalPushImageOptions, serverAddress string,
	username, password string, insecureSkipVerify bool) (string, error) {
	digest, err := getImageDigest(opts.Registry, serverAddress, opts.Repository, opts.Tag,
		username, password, insecureSkipVerify, false)
	if err != nil {
		digest, err = getImageDigest(opts.Registry, serverAddress, opts.Repository, opts.Tag,
			username, password, insecureSkipVerify, true)
		if err != nil {
			return "", fmt.Errorf("unable to get digest: %w", err)
		}
	}

	return digest, nil
}

func createPushImageOptions(image string) internalPushImageOptions {
	pullOpts := parseImageOptions(image)
	pushOpts := internalPushImageOptions{
		Name:               image,
		Registry:           pullOpts.Registry,
		NormalizedRegistry: normalizeRegistryAddress(pullOpts.Registry),
		Repository:         pullOpts.Repository,
		Tag:                pullOpts.Tag,
		FqName:             fmt.Sprintf("%s/%s:%s", pullOpts.Registry, pullOpts.Repository, pullOpts.Tag),
	}

	return pushOpts
}
