resource "docker_network" "tftest" {
  name = "tftest-contnw"
}

resource "docker_network" "tftest_2" {
  name = "tftest-contnw-2"
}

resource "docker_image" "foo" {
  name = "nginx:latest"
}

resource "docker_container" "foo" {
  name  = "tf-test"
  image = docker_image.foo.image_id
  network_mode = "bridge"  # Set explicitly
  cpu_shares   = 0         # Set explicitly
  memory       = 0         # Set explicitly
  memory_swap  = 0
  max_retry_count = 0

  networks_advanced {
    name = docker_network.tftest.name
  }
  networks_advanced {
    name = docker_network.tftest_2.name
  }
}
