resource "docker_image" "foo" {
  name = "nginx:latest"
}

resource "docker_container" "foo" {
  name       = "tf-test"
  image      = docker_image.foo.image_id
  stdin_open = true

  network_mode    = "bridge"
  cpu_shares      = 0
  memory          = 0
  memory_swap     = 0
  max_retry_count = 0
}
