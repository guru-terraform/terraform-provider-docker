resource "docker_image" "foo" {
  name = "nginx:latest"
}

resource "docker_container" "foo" {
  name  = "tf-test"
  image = docker_image.foo.image_id

  group_add = [
    "100"
  ]

  network_mode    = "bridge"  # Set explicitly
  cpu_shares      = 0         # Set optional fields explicitly
  memory          = 0
  memory_swap     = 0
  max_retry_count = 0
}
