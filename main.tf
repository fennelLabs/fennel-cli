module "gce-container" {
  source = "terraform-google-modules/container-vm/google"
  version = "~> 2.0" 

  container = {
    image = "ubuntu-os-cloud/ubuntu-2004-lts"
  }
}

resource "google_compute_address" "fennel-service-cli-ip" {
  name = "fennel-service-cli-ip"
}

resource "google_compute_instance" "fennel-service-cli" {
  name         = "fennel-service-cli-instance"
  machine_type = "e2-small"
  zone         = "us-east1-b"

  can_ip_forward = true
  tags = ["public-server"]
  
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = "whiteflag-sandbox-vpc"
    subnetwork = "public-subnet"
     access_config {
      nat_ip = google_compute_address.fennel-service-cli-ip.address
    }
  }

  metadata_startup_script = <<EOF
    #!/bin/bash
    apt-get update
    apt-get install -y docker.io
    gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin us-east1-docker.pkg.dev
    docker pull us-east1-docker.pkg.dev/whiteflag-0/fennel-docker-registry/fennel-service-cli:latest
    docker run -dit -p 9030:9030 --name fennel-service-cli us-east1-docker.pkg.dev/whiteflag-0/fennel-docker-registry/fennel-service-cli:latest
  EOF  

 metadata = {
    # Required metadata key.
    gce-container-declaration = module.gce-container.metadata_value
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
  }
 
  service_account {
    scopes = ["cloud-platform"]
  }
}
