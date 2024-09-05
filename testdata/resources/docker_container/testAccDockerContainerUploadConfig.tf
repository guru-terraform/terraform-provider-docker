resource "docker_image" "foo" {
  name         = "nginx:latest"
  keep_locally = true
}

resource "docker_container" "foo" {
  name         = "tf-test"
  image        = docker_image.foo.image_id
  cpu_shares   = 0
  memory       = 0
  memory_swap  = 0
  network_mode = "bridge"

  upload {
    content    = "foo"
    file       = "/terraform/test.txt"
    executable = true
  }
}
