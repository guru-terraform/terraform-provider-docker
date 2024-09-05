resource "docker_image" "foo_mounts" {
  name = "nginx:latest"
}

resource "docker_volume" "foo_mounts" {
  name = "testAccDockerContainerMounts_volume"
}

resource "docker_container" "foo_mounts" {
  name  = "tf-test"
  image = docker_image.foo_mounts.image_id

  mounts {
    target    = "/mount/test"
    source    = docker_volume.foo_mounts.name
    type      = "volume"
    read_only = true
  }
  mounts {
    target = "/mount/tmpfs"
    type   = "tmpfs"
  }

  network_mode    = "bridge"
  cpu_shares      = 0
  memory          = 0
  memory_swap     = 0
  max_retry_count = 0
}
