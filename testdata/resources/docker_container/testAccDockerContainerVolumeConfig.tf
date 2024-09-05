resource "docker_image" "foo" {
  name = "nginx:latest"
}

resource "docker_volume" "foo" {
  name = "testAccDockerContainerVolume_volume"
}

resource "docker_container" "foo" {
  name  = "tf-test"
  image = docker_image.foo.image_id

  volumes {
    volume_name    = docker_volume.foo.name
    container_path = "/tmp/volume"
    read_only      = false
  }

  network_mode    = "bridge"  # Set network_mode explicitly
  cpu_shares      = 0         # Set optional fields explicitly
  memory          = 0
  memory_swap     = 0
  max_retry_count = 0
}
