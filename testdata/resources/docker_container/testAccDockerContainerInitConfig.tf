resource "docker_image" "fooinit" {
  name = "nginx:latest"
}

resource "docker_container" "fooinit" {
  name             = "tf-test"
  image            = docker_image.fooinit.image_id
  init             = true
  network_mode     = "bridge"
  memory           = 0    # Set explicitly to prevent drift
  memory_swap      = 0
  cpu_shares       = 0
  max_retry_count  = 0
}
