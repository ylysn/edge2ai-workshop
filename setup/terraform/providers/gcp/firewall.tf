resource "google_compute_firewall" "private-access" {
  name = "${var.owner}-${replace(var.name_prefix ,".","-")}-private-access"
  description = "Allow ingress connections from the subnet IPs"
  network = google_compute_network.vpc[0].self_link
  allow {
    protocol    = "all"
  }
  source_ranges = [var.cidr_block_1]
  target_tags = ["${var.owner}-${replace(var.name_prefix ,".","-")}-private-access"]
}

resource "google_compute_firewall" "cluster-access" {
  name = "${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-access"
  description = "Allow ingress connections from the user public IPs"
  network = google_compute_network.vpc[0].self_link
  allow {
    protocol    = "all"
  }
  source_ranges = distinct(concat(["${var.my_public_ip}/32"], var.extra_cidr_blocks))
  target_tags = ["${var.owner}-${replace(var.name_prefix ,".","-")}-cluster-access"]
}

resource "google_compute_firewall" "web-access" {
  name = "${var.owner}-${replace(var.name_prefix ,".","-")}-web-access"
  description = "Allow ingress connections from the user public IPs"
  network = google_compute_network.vpc[0].self_link
  allow {
    protocol    = "all"
  }
  source_ranges = distinct(concat(["${var.my_public_ip}/32"], var.extra_cidr_blocks))
  target_tags = ["${var.owner}-${replace(var.name_prefix ,".","-")}-web-access"]
}

resource "google_compute_firewall" "workshop-cross-access" {
  name = "${var.owner}-${replace(var.name_prefix ,".","-")}-workshop-cross-access"
  description = "Cluster Public IP"
  network = google_compute_network.vpc[0].self_link
  allow {
    protocol    = "all"
  }

  source_ranges = flatten([
    [ for ip in (google_compute_address.cluster-public-ip.*.address): "${ip}/32" ],
    [ for ip in (google_compute_address.ecs-public-ip.*.address): "${ip}/32" ],
  ])
  target_tags = ["${var.owner}-${replace(var.name_prefix ,".","-")}-workshop-cross-access"]
}