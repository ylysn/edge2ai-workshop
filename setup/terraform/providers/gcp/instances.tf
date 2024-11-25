# cluster block
resource "google_compute_instance" "cluster" {
  count                   = var.cluster_count
  name                    = "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-${count.index}"
  machine_type            = var.cluster_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  hostname                = "cdp.${google_compute_address.cluster-public-ip[count.index].address}.nip.io"
  metadata_startup_script = "hostnamectl set-hostname $(curl -H Metadata-Flavor:Google http://metadata/computeMetadata/v1/instance/hostname) --static"

  tags = [
    "${var.owner}-${replace(var.name_prefix ,".","-")}-private-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-workshop-cross-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 200
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  attached_disk {
    source      = google_compute_disk.cluster-pd[count.index].self_link
    device_name = "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-pd-${count.index}-disk-0"
    mode        = "READ_WRITE"
  }

  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.cluster-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}

resource "google_compute_disk" "cluster-pd" {
  count = var.cluster_count
  name  = "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-pd-${count.index}"
  type  = "pd-balanced"
  zone  = "${var.gcp_region}-${var.gcp_az}"
  size  = 200
}

resource "google_compute_address" "cluster-public-ip" {
  count        = var.cluster_count
  name         = "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# web block
resource "google_compute_instance" "web" {
  count                   = (var.launch_web_server ? 1 : 0)
  name                    = "${var.owner}-${replace(var.name_prefix ,".","-")}-web"
  machine_type            = var.web_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  hostname                = "web.${google_compute_address.web-public-ip[count.index].address}.nip.io"
  metadata_startup_script = "hostnamectl set-hostname $(curl -H Metadata-Flavor:Google http://metadata/computeMetadata/v1/instance/hostname) --static"

  tags = [
    "${var.owner}-${replace(var.name_prefix ,".","-")}-private-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-web-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 20
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.web_ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.web-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}

resource "google_compute_address" "web-public-ip" {
  count        = (var.launch_web_server ? 1 : 0)
  name         = "${var.owner}-${replace(var.name_prefix ,".","-")}-web-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# ipa block
resource "google_compute_instance" "ipa" {
  count                   = (var.use_ipa ? 1 : 0)
  name                    = "${var.owner}-${replace(var.name_prefix ,".","-")}-ipa"
  machine_type            = var.ipa_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  hostname                = "ipa.${google_compute_address.ipa-public-ip[count.index].address}.nip.io"
  metadata_startup_script = "hostnamectl set-hostname $(curl -H Metadata-Flavor:Google http://metadata/computeMetadata/v1/instance/hostname) --static"

  tags = [
    "${var.owner}-${replace(var.name_prefix ,".","-")}-private-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-workshop-cross-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.cluster_ami
      size  = 20
      type  = "pd-balanced"
    }
    auto_delete = true
  }

  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.ipa-public-ip[count.index].address
    }
  }

  timeouts {
    create = "10m"
  }

}


resource "google_compute_address" "ipa-public-ip" {
  count        = (var.use_ipa ? 1 : 0)
  name         = "${var.owner}-${replace(var.name_prefix ,".","-")}-ipa-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# ecs block
resource "google_compute_instance" "ecs" {
  count                   = (var.pvc_data_services ? var.cluster_count : 0)
  name                    = "${var.owner}-${replace(var.name_prefix ,".","-")}-ecs-${count.index}"
  machine_type            = var.ecs_instance_type
  zone                    = "${var.gcp_region}-${var.gcp_az}"
  hostname                = "ecs.${google_compute_address.ecs-public-ip[count.index].address}.nip.io"
  metadata_startup_script = "hostnamectl set-hostname $(curl -H Metadata-Flavor:Google http://metadata/computeMetadata/v1/instance/hostname) --static"

  tags = [
    "${var.owner}-${replace(var.name_prefix ,".","-")}-private-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-workshop-cross-access",
    "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-access",
  ]

  boot_disk {
    initialize_params {
      image = var.ecs_ami
      size  = 500
      type  = "pd-balanced"
    }
    auto_delete = true
  }


  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.ssh_public_key)}"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet1.name

    access_config {
      nat_ip = google_compute_address.ecs-public-ip[count.index].address
    }
  }


  timeouts {
    create = "10m"
  }

}

resource "google_compute_address" "ecs-public-ip" {
  count        = (var.pvc_data_services ? var.cluster_count : 0)
  name         = "${var.owner}-${replace(var.name_prefix ,".","-")}-ecs-public-ip-${count.index}"
  address_type = "EXTERNAL"
}

# GCP instance group
resource "google_compute_instance_group" "servers" {
  name        = "${var.owner}-${replace(var.name_prefix ,".","-")}-servers"
  description = "${var.project}"

  instances = flatten([
    [for id in (google_compute_instance.cluster.*.self_link): id],
    [for id in (google_compute_instance.ecs.*.self_link): id],
    [for id in (google_compute_instance.web.*.self_link): id],
    [for id in (google_compute_instance.ipa.*.self_link): id],
  ])

  zone = "${var.gcp_region}-${var.gcp_az}"
}

