package provider

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"log"
	"os"
	"strings"
	"time"

	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-units"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	containerReadRefreshTimeoutMillisecondsDefault = 15000
	containerReadRefreshWaitBeforeRefreshes        = 100 * time.Millisecond
	containerReadRefreshDelay                      = 100 * time.Millisecond
)

var (
	errContainerFailedToBeCreated        = errors.New("container failed to be created")
	errContainerFailedToBeDeleted        = errors.New("container failed to be deleted")
	errContainerExitedImmediately        = errors.New("container exited immediately")
	errContainerFailedToBeInRunningState = errors.New("container failed to be in running state")
	errContainerFailedToBeInHealthyState = errors.New("container failed to be in healthy state")
)

// NOTE mavogel: we keep this global var for tracking
// the time in the create and read func
var creationTime time.Time

func resourceDockerContainerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var err error
	cli := meta.(*ProviderConfig).DockerClient
	authConfigs := meta.(*ProviderConfig).AuthConfigs
	image := d.Get("image").(string)
	_, err = findImage(ctx, image, cli, authConfigs, "")
	if err != nil {
		return diag.Errorf("Unable to create container with image %s: %s", image, err)
	}
	var stopTimeout *int
	if v, ok := d.GetOk("stop_timeout"); ok {
		tmp := v.(int)
		stopTimeout = &tmp
	}

	config := &container.Config{
		Image:       image,
		Hostname:    d.Get("hostname").(string),
		Domainname:  d.Get("domainname").(string),
		Tty:         d.Get("tty").(bool),
		OpenStdin:   d.Get("stdin_open").(bool),
		StopSignal:  d.Get("stop_signal").(string),
		StopTimeout: stopTimeout,
	}

	if v, ok := d.GetOk("env"); ok {
		config.Env = stringSetToStringSlice(v.(*schema.Set))
	}

	if v, ok := d.GetOk("command"); ok {
		config.Cmd = stringListToStringSlice(v.([]interface{}))
		for _, v := range config.Cmd {
			if v == "" {
				return diag.Errorf("values for command may not be empty")
			}
		}
	}

	if v, ok := d.GetOk("entrypoint"); ok {
		config.Entrypoint = stringListToStringSlice(v.([]interface{}))
	}

	if v, ok := d.GetOk("user"); ok {
		config.User = v.(string)
	}

	exposedPorts := map[nat.Port]struct{}{}
	portBindings := map[nat.Port][]nat.PortBinding{}

	if v, ok := d.GetOk("ports"); ok {
		exposedPorts, portBindings = portSetToDockerPorts(v.([]interface{}))
	}
	if len(exposedPorts) != 0 {
		config.ExposedPorts = exposedPorts
	}
	if v, ok := d.GetOk("working_dir"); ok {
		config.WorkingDir = v.(string)
	}
	extraHosts := []string{}
	if v, ok := d.GetOk("host"); ok {
		extraHosts = extraHostsSetToContainerExtraHosts(v.(*schema.Set))
	}

	extraUlimits := []*units.Ulimit{}
	if v, ok := d.GetOk("ulimit"); ok {
		extraUlimits = ulimitsToDockerUlimits(v.(*schema.Set))
	}
	volumes := map[string]struct{}{}
	binds := []string{}
	volumesFrom := []string{}

	if v, ok := d.GetOk("volumes"); ok {
		volumes, binds, volumesFrom, err = volumeSetToDockerVolumes(v.(*schema.Set))
		if err != nil {
			return diag.Errorf("Unable to parse volumes: %s", err)
		}
	}
	if len(volumes) != 0 {
		config.Volumes = volumes
	}

	if v, ok := d.GetOk("labels"); ok {
		config.Labels = labelSetToMap(v.(*schema.Set))
	}

	if value, ok := d.GetOk("healthcheck"); ok {
		config.Healthcheck = &container.HealthConfig{}
		if len(value.([]interface{})) > 0 {
			for _, rawHealthCheck := range value.([]interface{}) {
				rawHealthCheck := rawHealthCheck.(map[string]interface{})
				if testCommand, ok := rawHealthCheck["test"]; ok {
					config.Healthcheck.Test = stringListToStringSlice(testCommand.([]interface{}))
				}
				if rawInterval, ok := rawHealthCheck["interval"]; ok {
					config.Healthcheck.Interval, _ = time.ParseDuration(rawInterval.(string))
				}
				if rawTimeout, ok := rawHealthCheck["timeout"]; ok {
					config.Healthcheck.Timeout, _ = time.ParseDuration(rawTimeout.(string))
				}
				if rawStartPeriod, ok := rawHealthCheck["start_period"]; ok {
					config.Healthcheck.StartPeriod, _ = time.ParseDuration(rawStartPeriod.(string))
				}
				if rawRetries, ok := rawHealthCheck["retries"]; ok {
					config.Healthcheck.Retries, _ = rawRetries.(int)
				}
			}
		}
	}

	mounts := []mount.Mount{}

	if value, ok := d.GetOk("mounts"); ok {
		for _, rawMount := range value.(*schema.Set).List() {
			rawMount := rawMount.(map[string]interface{})
			mountType := mount.Type(rawMount["type"].(string))
			mountInstance := mount.Mount{
				Type:   mountType,
				Target: rawMount["target"].(string),
				Source: rawMount["source"].(string),
			}
			if value, ok := rawMount["read_only"]; ok {
				mountInstance.ReadOnly = value.(bool)
			}

			if mountType == mount.TypeBind {
				if value, ok := rawMount["bind_options"]; ok {
					if len(value.([]interface{})) > 0 {
						mountInstance.BindOptions = &mount.BindOptions{}
						for _, rawBindOptions := range value.([]interface{}) {
							rawBindOptions := rawBindOptions.(map[string]interface{})
							if value, ok := rawBindOptions["propagation"]; ok {
								mountInstance.BindOptions.Propagation = mount.Propagation(value.(string))
							}
						}
					}
				}
			} else if mountType == mount.TypeVolume {
				if value, ok := rawMount["volume_options"]; ok {
					if len(value.([]interface{})) > 0 {
						mountInstance.VolumeOptions = &mount.VolumeOptions{}
						for _, rawVolumeOptions := range value.([]interface{}) {
							rawVolumeOptions := rawVolumeOptions.(map[string]interface{})
							if value, ok := rawVolumeOptions["no_copy"]; ok {
								mountInstance.VolumeOptions.NoCopy = value.(bool)
							}
							if value, ok := rawVolumeOptions["labels"]; ok {
								mountInstance.VolumeOptions.Labels = labelSetToMap(value.(*schema.Set))
							}
							// because it is not possible to nest maps
							if value, ok := rawVolumeOptions["driver_name"]; ok {
								if mountInstance.VolumeOptions.DriverConfig == nil {
									mountInstance.VolumeOptions.DriverConfig = &mount.Driver{}
								}
								mountInstance.VolumeOptions.DriverConfig.Name = value.(string)
							}
							if value, ok := rawVolumeOptions["driver_options"]; ok {
								if mountInstance.VolumeOptions.DriverConfig == nil {
									mountInstance.VolumeOptions.DriverConfig = &mount.Driver{}
								}
								mountInstance.VolumeOptions.DriverConfig.Options = mapTypeMapValsToString(value.(map[string]interface{}))
							}
						}
					}
				}
			} else if mountType == mount.TypeTmpfs {
				if value, ok := rawMount["tmpfs_options"]; ok {
					if len(value.([]interface{})) > 0 {
						mountInstance.TmpfsOptions = &mount.TmpfsOptions{}
						for _, rawTmpfsOptions := range value.([]interface{}) {
							rawTmpfsOptions := rawTmpfsOptions.(map[string]interface{})
							if value, ok := rawTmpfsOptions["size_bytes"]; ok {
								mountInstance.TmpfsOptions.SizeBytes = (int64)(value.(int))
							}
							if value, ok := rawTmpfsOptions["mode"]; ok {
								mountInstance.TmpfsOptions.Mode = os.FileMode(value.(int))
							}
						}
					}
				}
			}

			mounts = append(mounts, mountInstance)
		}
	}

	restart := d.Get("restart").(string)
	hostConfig := &container.HostConfig{
		Privileged:      d.Get("privileged").(bool),
		PublishAllPorts: d.Get("publish_all_ports").(bool),
		RestartPolicy: container.RestartPolicy{
			Name:              container.RestartPolicyMode(restart),
			MaximumRetryCount: d.Get("max_retry_count").(int),
		},
		Runtime:        d.Get("runtime").(string),
		Mounts:         mounts,
		AutoRemove:     d.Get("rm").(bool),
		ReadonlyRootfs: d.Get("read_only").(bool),
		LogConfig: container.LogConfig{
			Type: d.Get("log_driver").(string),
		},
	}

	if v, ok := d.GetOk("tmpfs"); ok {
		hostConfig.Tmpfs = mapTypeMapValsToString(v.(map[string]interface{}))
	}

	if len(portBindings) != 0 {
		hostConfig.PortBindings = portBindings
	}
	if len(extraHosts) != 0 {
		hostConfig.ExtraHosts = extraHosts
	}
	if len(binds) != 0 {
		hostConfig.Binds = binds
	}
	if len(volumesFrom) != 0 {
		hostConfig.VolumesFrom = volumesFrom
	}
	if len(extraUlimits) != 0 {
		hostConfig.Ulimits = extraUlimits
	}

	if v, ok := d.GetOk("capabilities"); ok {
		for _, capInt := range v.(*schema.Set).List() {
			capa := capInt.(map[string]interface{})
			hostConfig.CapAdd = stringSetToStringSlice(capa["add"].(*schema.Set))
			hostConfig.CapDrop = stringSetToStringSlice(capa["drop"].(*schema.Set))
			break
		}
	}

	if v, ok := d.GetOk("devices"); ok {
		hostConfig.Devices = deviceSetToDockerDevices(v.(*schema.Set))
	}

	if v, ok := d.GetOk("dns"); ok {
		hostConfig.DNS = stringSetToStringSlice(v.(*schema.Set))
	}

	if v, ok := d.GetOk("dns_opts"); ok {
		hostConfig.DNSOptions = stringSetToStringSlice(v.(*schema.Set))
	}

	if v, ok := d.GetOk("dns_search"); ok {
		hostConfig.DNSSearch = stringSetToStringSlice(v.(*schema.Set))
	}

	if v, ok := d.GetOk("security_opts"); ok {
		hostConfig.SecurityOpt = stringSetToStringSlice(v.(*schema.Set))
	}

	if v, ok := d.GetOk("memory"); ok {
		hostConfig.Memory = int64(v.(int)) * 1024 * 1024
	}

	if v, ok := d.GetOk("memory_swap"); ok {
		swap := int64(v.(int))
		if swap > 0 {
			swap = swap * 1024 * 1024
		}
		hostConfig.MemorySwap = swap
	}

	if v, ok := d.GetOk("shm_size"); ok {
		hostConfig.ShmSize = int64(v.(int)) * 1024 * 1024
	}

	if v, ok := d.GetOk("cpu_shares"); ok {
		hostConfig.CPUShares = int64(v.(int))
	}

	if v, ok := d.GetOk("cpu_set"); ok {
		hostConfig.CpusetCpus = v.(string)
	}

	if v, ok := d.GetOk("log_opts"); ok {
		hostConfig.LogConfig.Config = mapTypeMapValsToString(v.(map[string]interface{}))
	}

	networkingConfig := &network.NetworkingConfig{}
	if v, ok := d.GetOk("network_mode"); ok {
		hostConfig.NetworkMode = container.NetworkMode(v.(string))
	}

	if v, ok := d.GetOk("userns_mode"); ok {
		hostConfig.UsernsMode = container.UsernsMode(v.(string))
	}
	if v, ok := d.GetOk("pid_mode"); ok {
		hostConfig.PidMode = container.PidMode(v.(string))
	}

	if v, ok := d.GetOk("sysctls"); ok {
		hostConfig.Sysctls = mapTypeMapValsToString(v.(map[string]interface{}))
	}
	if v, ok := d.GetOk("ipc_mode"); ok {
		hostConfig.IpcMode = container.IpcMode(v.(string))
	}
	if v, ok := d.GetOk("group_add"); ok {
		hostConfig.GroupAdd = stringSetToStringSlice(v.(*schema.Set))
	}
	if v, ok := d.GetOk("gpus"); ok {
		if cli.ClientVersion() >= "1.40" {
			var gpu opts.GpuOpts
			err := gpu.Set(v.(string))
			if err != nil {
				return diag.Errorf("Error setting gpus: %s", err)
			}
			hostConfig.DeviceRequests = gpu.Value()
		} else {
			log.Printf("[WARN] GPU support requires docker version 1.40 or higher")
		}
	}

	if v, ok := d.GetOk("cgroupns_mode"); ok {
		if cli.ClientVersion() >= "1.41" {
			cgroupnsMode := container.CgroupnsMode(v.(string))
			if !cgroupnsMode.Valid() {
				return diag.Errorf("cgroupns_mode: invalid CGROUP mode, must be either 'private', 'host' or empty")
			} else {
				hostConfig.CgroupnsMode = cgroupnsMode
			}
		} else {
			log.Printf("[WARN] cgroupns_mode requires docker version 1.41 or higher")
		}
	}

	init := d.Get("init").(bool)
	hostConfig.Init = &init

	if v, ok := d.GetOk("storage_opts"); ok {
		hostConfig.StorageOpt = mapTypeMapValsToString(v.(map[string]interface{}))
	}

	var retContainer container.CreateResponse

	// TODO mavogel add platform later which comes from API v1.41. Currently we pass nil
	if retContainer, err = cli.ContainerCreate(ctx, config, hostConfig, networkingConfig, nil, d.Get("name").(string)); err != nil {
		return diag.Errorf("Unable to create container: %s", err)
	}
	log.Printf("[INFO] retContainer %#v", retContainer)
	d.SetId(retContainer.ID)

	// But overwrite them with the future ones, if set
	if v, ok := d.GetOk("networks_advanced"); ok {
		if err := cli.NetworkDisconnect(ctx, "bridge", retContainer.ID, false); err != nil {
			if !containsIgnorableErrorMessage(err.Error(), "is not connected to the network bridge") {
				return diag.Errorf("Unable to disconnect the default network: %s", err)
			}
		}

		for _, rawNetwork := range v.(*schema.Set).List() {
			networkID := rawNetwork.(map[string]interface{})["name"].(string)

			endpointConfig := &network.EndpointSettings{}
			endpointIPAMConfig := &network.EndpointIPAMConfig{}
			if v, ok := rawNetwork.(map[string]interface{})["aliases"]; ok {
				endpointConfig.Aliases = stringSetToStringSlice(v.(*schema.Set))
			}
			if v, ok := rawNetwork.(map[string]interface{})["ipv4_address"]; ok {
				endpointIPAMConfig.IPv4Address = v.(string)
			}
			if v, ok := rawNetwork.(map[string]interface{})["ipv6_address"]; ok {
				endpointIPAMConfig.IPv6Address = v.(string)
			}
			endpointConfig.IPAMConfig = endpointIPAMConfig

			if err := cli.NetworkConnect(ctx, networkID, retContainer.ID, endpointConfig); err != nil {
				return diag.Errorf("Unable to connect to network '%s': %s", networkID, err)
			}
		}
	}

	if v, ok := d.GetOk("upload"); ok {

		var mode int64
		for _, upload := range v.(*schema.Set).List() {
			content := upload.(map[string]interface{})["content"].(string)
			contentBase64 := upload.(map[string]interface{})["content_base64"].(string)
			source := upload.(map[string]interface{})["source"].(string)

			testParams := []string{content, contentBase64, source}
			setParams := 0
			for _, v := range testParams {
				if v != "" {
					setParams++
				}
			}

			if setParams == 0 {
				return diag.Errorf("error with upload content: one of 'content', 'content_base64', or 'source' must be set")
			}
			if setParams > 1 {
				return diag.Errorf("error with upload content: only one of 'content', 'content_base64', or 'source' can be set")
			}

			var contentToUpload string
			if content != "" {
				contentToUpload = content
			}
			if contentBase64 != "" {
				decoded, _ := base64.StdEncoding.DecodeString(contentBase64)
				contentToUpload = string(decoded)
			}
			if source != "" {
				sourceContent, err := os.ReadFile(source)
				if err != nil {
					return diag.Errorf("could not read file: %s", err)
				}
				contentToUpload = string(sourceContent)
			}
			file := upload.(map[string]interface{})["file"].(string)
			executable := upload.(map[string]interface{})["executable"].(bool)

			buf := new(bytes.Buffer)
			tw := tar.NewWriter(buf)
			if executable {
				mode = 0o744
			} else {
				mode = 0o644
			}
			hdr := &tar.Header{
				Name:    file,
				Mode:    mode,
				Size:    int64(len(contentToUpload)),
				ModTime: time.Now(),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return diag.Errorf("Error creating tar archive: %s", err)
			}
			if _, err := tw.Write([]byte(contentToUpload)); err != nil {
				return diag.Errorf("Error creating tar archive: %s", err)
			}
			if err := tw.Close(); err != nil {
				return diag.Errorf("Error creating tar archive: %s", err)
			}

			dstPath := "/"
			uploadContent := bytes.NewReader(buf.Bytes())
			options := container.CopyToContainerOptions{}
			if err := cli.CopyToContainer(ctx, retContainer.ID, dstPath, uploadContent, options); err != nil {
				return diag.Errorf("Unable to upload volume content: %s", err)
			}
		}
	}

	if d.Get("start").(bool) {
		creationTime = time.Now()
		options := container.StartOptions{}
		if err := cli.ContainerStart(ctx, retContainer.ID, options); err != nil {
			return diag.Errorf("Unable to start container: %s", err)
		}

		if d.Get("wait").(bool) {
			waitForHealthyState := func(result chan<- error) {
				for {
					infos, err := cli.ContainerInspect(ctx, retContainer.ID)
					if err != nil {
						result <- fmt.Errorf("error inspecting container state: %s", err)
					}
					//infos.ContainerJSONBase.State.Health is only set when there is a healthcheck defined on the container resource
					if infos.ContainerJSONBase.State.Health.Status == types.Healthy {
						log.Printf("[DEBUG] container state is healthy")
						break
					}
					log.Printf("[DEBUG] waiting for container healthy state")
					time.Sleep(time.Second)
				}
				result <- nil
			}

			ctx, cancel := context.WithTimeout(ctx, time.Duration(d.Get("wait_timeout").(int))*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go waitForHealthyState(result)
			select {
			case <-ctx.Done():
				log.Printf("[ERROR] Container %s failed to be in healthy state in time", retContainer.ID)
				return diag.FromErr(errContainerFailedToBeInHealthyState)

			case err := <-result:
				if err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	if d.Get("attach").(bool) {
		var b bytes.Buffer
		logsRead := make(chan bool)
		if d.Get("logs").(bool) {
			go func() {
				defer func() { logsRead <- true }()
				reader, err := cli.ContainerLogs(ctx, retContainer.ID, container.LogsOptions{
					ShowStdout: true,
					ShowStderr: true,
					Follow:     true,
					Timestamps: false,
				})
				if err != nil {
					log.Panic(err)
				}
				defer reader.Close()

				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					line := scanner.Text()
					b.WriteString(line)
					b.WriteString("\n")

					log.Printf("[DEBUG] container logs: %s", line)
				}
				if err := scanner.Err(); err != nil {
					log.Fatal(err)
				}
			}()
		}

		attachCh, errAttachCh := cli.ContainerWait(ctx, retContainer.ID, container.WaitConditionNotRunning)
		select {
		case err := <-errAttachCh:
			if err != nil {
				return diag.Errorf("Unable to wait container end of execution: %s", err)
			}
		case <-attachCh:
			if d.Get("logs").(bool) {
				// There is a race condition here.
				// If the goroutine does not finish writing into the buffer by this line, we will have no logs.
				// Thus, waiting for the goroutine to finish
				<-logsRead
				d.Set("container_logs", b.String())
			}
		}
	}

	return resourceDockerContainerRead(ctx, d, meta)
}

func resourceDockerContainerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	containerReadRefreshTimeoutMilliseconds := d.Get("container_read_refresh_timeout_milliseconds").(int)
	// Ensure the timeout can never be 0, the default integer value.
	// This also ensures imported resources will get the default of 15 seconds
	if containerReadRefreshTimeoutMilliseconds == 0 {
		containerReadRefreshTimeoutMilliseconds = containerReadRefreshTimeoutMillisecondsDefault
	}
	log.Printf("[INFO] Waiting for container: '%s' to run: max '%v seconds'", d.Id(), containerReadRefreshTimeoutMilliseconds/1000)
	cli := meta.(*ProviderConfig).DockerClient

	apiContainer, err := fetchDockerContainer(ctx, d.Id(), cli)
	if err != nil {
		return diag.FromErr(err)
	}
	if apiContainer == nil {
		// This container doesn't exist anymore
		d.SetId("")
		return nil
	}

	stateConf := &retry.StateChangeConf{
		Pending:    []string{"pending"},
		Target:     []string{"running"},
		Refresh:    resourceDockerContainerReadRefreshFunc(ctx, d, meta),
		Timeout:    time.Duration(containerReadRefreshTimeoutMilliseconds) * time.Millisecond,
		MinTimeout: containerReadRefreshWaitBeforeRefreshes,
		Delay:      containerReadRefreshDelay,
	}

	containerRaw, err := stateConf.WaitForStateContext(ctx)
	if err != nil {
		if errors.Is(err, errContainerFailedToBeCreated) {
			return resourceDockerContainerDelete(ctx, d, meta)
		}
		if errors.Is(err, errContainerExitedImmediately) {
			if err := resourceDockerContainerDelete(ctx, d, meta); err != nil {
				log.Printf("[ERROR] Container %s failed to be deleted: %v", apiContainer.ID, err)
				return diag.FromErr(errContainerFailedToBeDeleted)
			}
		}
		return diag.FromErr(err)
	}

	cont := containerRaw.(types.ContainerJSON)
	jsonObj, _ := json.MarshalIndent(cont, "", "\t")
	log.Printf("[DEBUG] Docker container inspect from stateFunc: %s", jsonObj)

	if !cont.State.Running && d.Get("must_run").(bool) {
		if err := resourceDockerContainerDelete(ctx, d, meta); err != nil {
			log.Printf("[ERROR] Container %s failed to be deleted: %v", cont.ID, err)
			return err
		}
		log.Printf("[ERROR] Container %s failed to be in running state", cont.ID)
		return diag.FromErr(errContainerFailedToBeInRunningState)
	}

	if !cont.State.Running {
		d.Set("exit_code", cont.State.ExitCode)
	}

	// Read Network Settings
	if cont.NetworkSettings != nil {
		d.Set("bridge", cont.NetworkSettings.Bridge)
		if err := d.Set("ports", flattenContainerPorts(cont.NetworkSettings.Ports)); err != nil {
			log.Printf("[WARN] failed to set ports from API: %s", err)
		}
		if err := d.Set("network_data", flattenContainerNetworks(cont.NetworkSettings)); err != nil {
			log.Printf("[WARN] failed to set network settings from API: %s", err)
		}
	}

	// TODO all the other attributes
	d.SetId(cont.ID)
	d.Set("name", strings.TrimLeft(cont.Name, "/")) // api prefixes with '/' ...
	d.Set("rm", cont.HostConfig.AutoRemove)
	d.Set("read_only", cont.HostConfig.ReadonlyRootfs)
	// "start" can't be imported
	// attach
	// logs
	// "must_run" can't be imported
	// container_logs
	d.Set("image", cont.Image)
	d.Set("hostname", cont.Config.Hostname)
	d.Set("domainname", cont.Config.Domainname)
	d.Set("command", cont.Config.Cmd)
	d.Set("entrypoint", cont.Config.Entrypoint)
	d.Set("user", cont.Config.User)
	d.Set("dns", cont.HostConfig.DNS)
	d.Set("dns_opts", cont.HostConfig.DNSOptions)
	d.Set("security_opts", cont.HostConfig.SecurityOpt)
	d.Set("dns_search", cont.HostConfig.DNSSearch)
	d.Set("publish_all_ports", cont.HostConfig.PublishAllPorts)
	d.Set("restart", cont.HostConfig.RestartPolicy.Name)
	d.Set("max_retry_count", cont.HostConfig.RestartPolicy.MaximumRetryCount)

	// From what I can tell Init being nullable is only for container creation to allow
	// dockerd to default it to the daemons own default settings. So this != nil
	// check is most likely not ever going to fail. In the event that it does the
	// "init" value will be set to false as there isn't much else we can do about it.
	if cont.HostConfig.Init != nil {
		d.Set("init", *cont.HostConfig.Init)
	} else {
		d.Set("init", false)
	}
	d.Set("working_dir", cont.Config.WorkingDir)
	if len(cont.HostConfig.CapAdd) > 0 || len(cont.HostConfig.CapDrop) > 0 {
		// TODO implement DiffSuppressFunc
		d.Set("capabilities", []interface{}{
			map[string]interface{}{
				"add":  cont.HostConfig.CapAdd,
				"drop": cont.HostConfig.CapDrop,
			},
		})
	}
	d.Set("runtime", cont.HostConfig.Runtime)
	d.Set("mounts", getDockerContainerMounts(cont))
	// volumes
	d.Set("tmpfs", cont.HostConfig.Tmpfs)
	if err := d.Set("host", flattenExtraHosts(cont.HostConfig.ExtraHosts)); err != nil {
		log.Printf("[WARN] failed to set container hostconfig extrahosts from API: %s", err)
	}
	if err = d.Set("ulimit", flattenUlimits(cont.HostConfig.Ulimits)); err != nil {
		log.Printf("[WARN] failed to set container hostconfig  ulimits from API: %s", err)
	}

	// We decided not to set the environment variables and labels
	// because they are taken over from the Docker image and aren't scalar
	// so it's difficult to treat them well.
	// For detail, please see the following URLs.
	// https://github.com/guru-terraform/docker-provider/issues/242
	// https://github.com/guru-terraform/docker-provider/pull/269

	d.Set("privileged", cont.HostConfig.Privileged)
	if err = d.Set("devices", flattenDevices(cont.HostConfig.Devices)); err != nil {
		log.Printf("[WARN] failed to set container hostconfig devices from API: %s", err)
	}
	// "destroy_grace_seconds" can't be imported
	d.Set("memory", cont.HostConfig.Memory/1024/1024)
	if cont.HostConfig.MemorySwap > 0 {
		d.Set("memory_swap", cont.HostConfig.MemorySwap/1024/1024)
	} else {
		d.Set("memory_swap", cont.HostConfig.MemorySwap)
	}
	d.Set("shm_size", cont.HostConfig.ShmSize/1024/1024)
	d.Set("cpu_shares", cont.HostConfig.CPUShares)
	d.Set("cpu_set", cont.HostConfig.CpusetCpus)
	d.Set("log_driver", cont.HostConfig.LogConfig.Type)
	d.Set("log_opts", cont.HostConfig.LogConfig.Config)
	d.Set("storage_opts", cont.HostConfig.StorageOpt)
	d.Set("network_mode", cont.HostConfig.NetworkMode)
	d.Set("pid_mode", cont.HostConfig.PidMode)
	d.Set("userns_mode", cont.HostConfig.UsernsMode)
	// "upload" can't be imported
	if cont.Config.Healthcheck != nil {
		d.Set("healthcheck", []interface{}{
			map[string]interface{}{
				"test":         cont.Config.Healthcheck.Test,
				"interval":     cont.Config.Healthcheck.Interval.String(),
				"timeout":      cont.Config.Healthcheck.Timeout.String(),
				"start_period": cont.Config.Healthcheck.StartPeriod.String(),
				"retries":      cont.Config.Healthcheck.Retries,
			},
		})
	}
	d.Set("sysctls", cont.HostConfig.Sysctls)
	d.Set("ipc_mode", cont.HostConfig.IpcMode)
	d.Set("group_add", cont.HostConfig.GroupAdd)
	d.Set("tty", cont.Config.Tty)
	d.Set("stdin_open", cont.Config.OpenStdin)
	d.Set("stop_signal", cont.Config.StopSignal)
	d.Set("stop_timeout", cont.Config.StopTimeout)

	if len(cont.HostConfig.DeviceRequests) > 0 {
		// TODO pass the original gpus property string back to the resource
		// var gpuOpts opts.GpuOpts
		// gpuOpts = opts.GpuOpts{container.HostConfig.DeviceRequests}
		d.Set("gpus", "all")
	}

	return nil
}

func resourceDockerContainerReadRefreshFunc(ctx context.Context,
	d *schema.ResourceData, meta interface{}) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		client := meta.(*ProviderConfig).DockerClient
		containerID := d.Id()

		var container types.ContainerJSON
		container, err := client.ContainerInspect(ctx, containerID)
		if err != nil {
			return container, "pending", err
		}

		jsonObj, _ := json.MarshalIndent(container, "", "\t")
		log.Printf("[DEBUG] Docker container inspect: %s", jsonObj)

		if container.State.Running ||
			!container.State.Running && !d.Get("must_run").(bool) {
			log.Printf("[DEBUG] Container %s is running: %v", containerID, container.State.Running)
			return container, "running", nil
		}

		if creationTime.IsZero() { // We didn't just create it, so don't wait around
			log.Printf("[DEBUG] Container %s was not created", containerID)
			return container, "pending", errContainerFailedToBeCreated
		}

		finishTime, err := time.Parse(time.RFC3339, container.State.FinishedAt)
		if err != nil {
			log.Printf("[ERROR] Container %s finish time could not be parsed: %s", containerID, container.State.FinishedAt)
			return container, "pending", err
		}
		if finishTime.After(creationTime) {
			log.Printf("[INFO] Container %s exited immediately: started: %v - finished: %v", containerID, creationTime, finishTime)
			return container, "pending", errContainerExitedImmediately
		}

		// TODO mavogel wait until all properties are exposed from the API
		// dns               = []
		// dns_opts          = []
		// dns_search        = []
		// group_add         = []
		// id                = "9e6d9e987923e2c3a99f17e8781c7ce3515558df0e45f8ab06f6adb2dda0de50"
		// log_opts          = {}
		// name              = "nginx"
		// sysctls           = {}
		// tmpfs             = {}

		return container, "running", nil
	}
}

func resourceDockerContainerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	attrs := []string{
		"restart", "max_retry_count", "cpu_shares", "memory", "cpu_set", "memory_swap",
	}
	for _, attr := range attrs {
		if d.HasChange(attr) {

			// TODO update ulimits
			// Updating ulimits seems not to work well.
			// It succeeds to run `DockerClient.ContainerUpdate` with `ulimit` but actually `ulimit` aren't changed.
			// https://github.com/guru-terraform/docker-provider/pull/236#discussion_r373819536
			// ulimits := []*units.Ulimit{}
			// if v, ok := d.GetOk("ulimit"); ok {
			// 	ulimits = ulimitsToDockerUlimits(v.(*schema.Set))
			// }

			restart := d.Get("restart").(string)
			updateConfig := container.UpdateConfig{
				RestartPolicy: container.RestartPolicy{
					Name:              container.RestartPolicyMode(restart),
					MaximumRetryCount: d.Get("max_retry_count").(int),
				},
				Resources: container.Resources{
					CPUShares:  int64(d.Get("cpu_shares").(int)),
					Memory:     int64(d.Get("memory").(int)) * 1024 * 1024,
					CpusetCpus: d.Get("cpu_set").(string),
					// Ulimits:    ulimits,
				},
			}

			if ms, ok := d.GetOk("memory_swap"); ok {
				a := int64(ms.(int))
				if a > 0 {
					a = a * 1024 * 1024
				}
				updateConfig.Resources.MemorySwap = a
			}
			client := meta.(*ProviderConfig).DockerClient
			_, err := client.ContainerUpdate(ctx, d.Id(), updateConfig)
			if err != nil {
				return diag.Errorf("Unable to update a container: %v", err)
			}
			break
		}
	}
	return nil
}

func resourceDockerContainerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*ProviderConfig).DockerClient

	if !d.Get("attach").(bool) {
		// Stop the container before removing if destroy_grace_seconds is defined
		var timeout time.Duration
		if d.Get("destroy_grace_seconds").(int) > 0 {
			timeout = time.Duration(int32(d.Get("destroy_grace_seconds").(int))) * time.Second
		}

		iTimeout := int(timeout.Seconds())
		log.Printf("[INFO] Stopping Container '%s' with timeout %v", d.Id(), timeout)
		if err := client.ContainerStop(ctx, d.Id(), container.StopOptions{Timeout: &iTimeout}); err != nil {
			return diag.Errorf("Error stopping container %s: %s", d.Id(), err)
		}
	}

	removeOpts := container.RemoveOptions{
		RemoveVolumes: d.Get("remove_volumes").(bool),
		RemoveLinks:   d.Get("rm").(bool),
		Force:         true,
	}

	log.Printf("[INFO] Removing Container '%s'", d.Id())
	if err := client.ContainerRemove(ctx, d.Id(), removeOpts); err != nil {
		if !containsIgnorableErrorMessage(err.Error(), "No such container", "is already in progress") {
			return diag.Errorf("Error deleting container %s: %s", d.Id(), err)
		}
	}

	waitCondition := container.WaitConditionNotRunning
	if d.Get("rm").(bool) {
		waitCondition = container.WaitConditionRemoved
	}

	log.Printf("[INFO] Waiting for Container '%s' with condition '%s'", d.Id(), waitCondition)
	waitOkC, errorC := client.ContainerWait(ctx, d.Id(), waitCondition)
	select {
	case waitOk := <-waitOkC:
		log.Printf("[INFO] Container exited with code [%v]: '%s'", waitOk.StatusCode, d.Id())
	case err := <-errorC:
		if !containsIgnorableErrorMessage(err.Error(), "No such container", "is already in progress") {
			return diag.Errorf("Error waiting for container removal '%s': %s", d.Id(), err)
		}
		log.Printf("[INFO] Waiting for Container '%s' errord: '%s'", d.Id(), err.Error())
	}

	d.SetId("")
	return nil
}

func fetchDockerContainer(ctx context.Context, ID string, client *client.Client) (*types.Container, error) {
	apiContainers, err := client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("error fetching container information from Docker: %s\n", err)
	}

	for _, apiContainer := range apiContainers {
		if apiContainer.ID == ID {
			return &apiContainer, nil
		}
	}

	return nil, nil
}
