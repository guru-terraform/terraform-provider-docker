resource "docker_image" "foo" {
  name         = "nginx:latest"
  keep_locally = true
}

resource "docker_container" "foo" {
  name  = "tf-test"
  image = docker_image.foo.image_id

  # Explicitly set network_mode to prevent forced replacement
  network_mode = "bridge"

  # Set explicit values for attributes that were changing
  command     = ["nginx", "-g", "daemon off;"]
  entrypoint  = ["/docker-entrypoint.sh"]
  env         = []
  init        = false
  ipc_mode    = "private"
  log_driver  = "json-file"
  runtime     = "runc"
  security_opts = []
  shm_size    = 64
  stop_signal = "SIGQUIT"
  stop_timeout = 0

  # Explicitly set attributes that were being removed
  cpu_shares      = 0
  max_retry_count = 0
  memory          = 0
  memory_swap     = 0
  privileged      = false
  publish_all_ports = false

  # Ignore changes to certain attributes that may vary between applies
  lifecycle {
    ignore_changes = [
      healthcheck,
      labels,
      hostname,
      id,
      network_data
    ]
  }
}
