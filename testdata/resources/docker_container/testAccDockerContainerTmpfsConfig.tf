resource "docker_image" "foo" {
  name = "nginx:latest"
}

resource "docker_container" "foo" {
  name  = "tf-test"
  image = docker_image.foo.image_id

  tmpfs = {
    "/mount/tmpfs" = "rw,noexec,nosuid"
  }

  network_mode    = "bridge"  # Set network mode explicitly
  cpu_shares      = 0         # Set optional fields to avoid null
  memory          = 0
  memory_swap     = 0
  max_retry_count = 0
}
