#region Variables

variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "aws_region" {}
variable "aws_ssh_key_name" {}
variable "aws_ssh_key_path" {}
variable "telegraf_config_path" {}
variable "ql_root_ca_path" {}
variable "ql_sub_ca_path" {}
variable "docker_dtr_cert_path" {}
variable "docker_dtr_key_path" {}
variable "ucp_admin_username" {}
variable "ucp_admin_password" {}
variable "docker_ucp_cert_path" {}
variable "docker_ucp_key_path" {}
variable "daemon_json_path" {}
variable "docker_ee_repo" {}
variable "docker_license_file_path" {}
variable "aws_ucp_iam_cert_name" {}
variable "iam_ucp_cert_body_path" {}
variable "iam_ucp_cert_chain_path" {}
variable "aws_dtr_iam_cert_name" {}
variable "iam_dtr_cert_body_path" {}
variable "iam_dtr_cert_chain_path" {}
variable "total_number_of_UCP_nodes" {}
variable "lambda_payload_path" {}

#endregion

#region Provider

provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "${var.aws_region}"
}

data "aws_region" "current" {}

#endregion

#region IAM Certs

resource "aws_iam_server_certificate" "DockerLab_UCP_cert" {
  name_prefix       = "${var.aws_ucp_iam_cert_name}-"
  certificate_body  = "${file(var.iam_ucp_cert_body_path)}"
  certificate_chain = "${file(var.iam_ucp_cert_chain_path)}"
  private_key       = "${file(var.docker_ucp_key_path)}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_server_certificate" "DockerLab_DTR_cert" {
  name_prefix       = "${var.aws_dtr_iam_cert_name}-"
  certificate_body  = "${file(var.iam_dtr_cert_body_path)}"
  certificate_chain = "${file(var.iam_dtr_cert_chain_path)}"
  private_key       = "${file(var.docker_dtr_key_path)}"

  lifecycle {
    create_before_destroy = true
  }
}

#endregion

#region IAM Policies

data "aws_iam_policy" "AmazonSSMFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

data "aws_iam_policy" "AmazonEC2RoleforSSM" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

data "aws_iam_policy" "AWSLambdaBasicExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy" "AmazonEC2ReadOnlyAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

data "aws_iam_policy" "AWSLambdaRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"
}

data "aws_iam_policy" "AWSLambdaVPCAccessExecutionRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}


resource "aws_iam_policy" "ASG_Lifecycle_Policy" {
  name        = "Terra-ASG-Lifecycle-Policy"
  path        = "/"
  description = "Terra-ASG-Lifecycle-Policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "autoscaling:CompleteLifecycleAction",
        "sns:Publish"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

#endregion

#region IAM stuff

data "aws_iam_policy" "AutoScalingNotificationAccessRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AutoScalingNotificationAccessRole"
}

resource "aws_iam_role" "DockerLabTerraAssumeRole" {
  name = "DockerLabTerraAssumeRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role" "Terra_SNS_Role" {
  name = "TerraSNSRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "autoscaling.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "Attach_AutoScalingNotificationAccessRole_to_Terra_SNS_Role" {
  role       = "${aws_iam_role.Terra_SNS_Role.name}"
  policy_arn = "${data.aws_iam_policy.AutoScalingNotificationAccessRole.arn}"
}

resource "aws_iam_instance_profile" "DockerLabTerraInstanceProfile" {
  name = "DockerLabTerraInstanceProfile"

  role = "DockerLabTerraAssumeRole"
}

resource "aws_iam_role_policy" "DockerLabTerraAssumeRolePolicy" {
  name = "DockerLabTerraAssumeRolePolicy"
  role = "${aws_iam_role.DockerLabTerraAssumeRole.id}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "Attach_AmazonEC2RoleforSSM_to_DockerLabTerraAssumeRole" {
  role       = "${aws_iam_role.DockerLabTerraAssumeRole.name}"
  policy_arn = "${data.aws_iam_policy.AmazonEC2RoleforSSM.arn}"
}

#resource "aws_iam_role_policy_attachment" "Attach_DockerLabTerraAssumeRolePolicy_to_DockerLabTerraAssumeRole" {
# role = "${aws_iam_role.DockerLabTerraAssumeRole.name}"
#policy_arn = "${aws_iam_role_policy.DockerLabTerraAssumeRolePolicy.arn}"
#}
resource "aws_iam_role_policy_attachment" "Attach_ASG_Lifecycle_Policy_to_DockerLabTerraAssumeRole" {
  role       = "${aws_iam_role.DockerLabTerraAssumeRole.name}"
  policy_arn = "${aws_iam_policy.ASG_Lifecycle_Policy.arn}"
}
resource "aws_iam_role_policy_attachment" "Attach_AmazonEC2ReadOnlyAccess_to_DockerLabTerraAssumeRole" {
  role       = "${aws_iam_role.DockerLabTerraAssumeRole.name}"
  policy_arn = "${data.aws_iam_policy.AmazonEC2ReadOnlyAccess.arn}"
}

resource "aws_iam_role" "Terra_Lambda_Role" {
  name = "Terra-Lambda-Role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "Attach_AmazonSSMFullAccess_to_Terra_Lambda_Role" {
  role       = "${aws_iam_role.Terra_Lambda_Role.name}"
  policy_arn = "${data.aws_iam_policy.AmazonSSMFullAccess.arn}"
}

resource "aws_iam_role_policy_attachment" "Attach_AWSLambdaVPCAccessExecutionRole_to_Terra_Lambda_Role" {
  role       = "${aws_iam_role.Terra_Lambda_Role.name}"
  policy_arn = "${data.aws_iam_policy.AWSLambdaVPCAccessExecutionRole.arn}"
}


resource "aws_iam_role_policy_attachment" "Attach_AWSLambdaRole_to_Terra_Lambda_Role" {
  role       = "${aws_iam_role.Terra_Lambda_Role.name}"
  policy_arn = "${data.aws_iam_policy.AWSLambdaRole.arn}"
}

resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole_to_Terra_Lambda_Role" {
  role       = "${aws_iam_role.Terra_Lambda_Role.name}"
  policy_arn = "${data.aws_iam_policy.AWSLambdaBasicExecutionRole.arn}"
}

resource "aws_iam_role_policy_attachment" "ASG_Lifecycle_Policy_to_Terra_Lambda_Role" {
  role       = "${aws_iam_role.Terra_Lambda_Role.name}"
  policy_arn = "${aws_iam_policy.ASG_Lifecycle_Policy.arn}"
}

#endregion

#region VPC

resource "aws_vpc" "DockerLabVPC" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_hostnames = true

  tags {
    Name = "Docker Lab"
  }
}

data "aws_availability_zones" "available" {}

resource "aws_internet_gateway" "DockerLabIG" {
  vpc_id = "${aws_vpc.DockerLabVPC.id}"

  tags {
    Name = "DockerLabIG"
  }
}

resource "aws_route_table" "default" {
  vpc_id = "${aws_vpc.DockerLabVPC.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.DockerLabIG.id}"
  }

  tags {
    Name = "DockerLabRT"
  }
}

resource "aws_main_route_table_association" "MainRoute" {
  vpc_id         = "${aws_vpc.DockerLabVPC.id}"
  route_table_id = "${aws_route_table.default.id}"
}

#endregion

#region Subnets

resource "aws_subnet" "az_subnets" {
  vpc_id            = "${aws_vpc.DockerLabVPC.id}"
  count             = "${length(data.aws_availability_zones.available.names)}"
  cidr_block        = "10.10.${count.index + 1}.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"

  tags {
    Name = "${data.aws_availability_zones.available.names[count.index]}"
  }
}

#endregion

#region Route 53 Records

data "aws_route53_zone" "dockersandbox_foc_zone" {
  name         = "dockersandbox.foc.zone."
  private_zone = false
}

resource "aws_route53_record" "terraucp" {
  zone_id = "${data.aws_route53_zone.dockersandbox_foc_zone.zone_id}"
  name    = "terraucp.${data.aws_route53_zone.dockersandbox_foc_zone.name}"
  type    = "CNAME"
  ttl     = "60"
  records = ["${aws_lb.Docker_UCP_External_LB.dns_name}"]
}

resource "aws_route53_record" "terrainternalucp" {
  zone_id = "${data.aws_route53_zone.dockersandbox_foc_zone.zone_id}"
  name    = "terrainternalucp.${data.aws_route53_zone.dockersandbox_foc_zone.name}"
  type    = "CNAME"
  ttl     = "60"
  records = ["${aws_lb.Docker_UCP_External_LB.dns_name}"]
}

resource "aws_route53_record" "terradtr" {
  zone_id = "${data.aws_route53_zone.dockersandbox_foc_zone.zone_id}"
  name    = "terradtr.${data.aws_route53_zone.dockersandbox_foc_zone.name}"
  type    = "CNAME"
  ttl     = "60"
  records = ["${aws_lb.Docker_DTR_External_LB.dns_name}"]
}

#endregion

#region Security Groups

resource "aws_security_group" "From_QL_Public" {
  name        = "From QL Public"
  description = "Allow SSH from QL Public IPs"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["162.252.136.0/22"]
  }
}

resource "aws_security_group" "egress" {
  name        = "All egress"
  description = "Allow all egress traffic"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "QL_On_Prem" {
  name        = "From QL Public On-Prem"
  description = "Allow all traffic from QL Private IPs"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "Docker_Linux_Nodes" {
  name        = "Docker Linux Nodes"
  description = "Docker Linux Nodes"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    description = "QL On-Prem F5s"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"

    cidr_blocks = [
      "10.101.0.0/24",
      "10.102.0.0/24",
      "10.121.0.0/24",
      "10.122.0.0/24",
    ]
  }

  ingress {
    description = "QL LDAP Query"
    from_port   = 0
    to_port     = 0
    protocol    = -1

    cidr_blocks = [
      "10.2.122.100/32",
      "10.9.122.100/32",
    ]
  }

  ingress {
    description = "Public IP to instance 443"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  ingress {
    description = "QL Splunk"
    from_port   = 0
    to_port     = 0
    protocol    = -1

    cidr_blocks = [
      "10.161.39.0/24",
      "10.162.39.0/24",
    ]
  }

  ingress {
    description = "QL to UCP UI"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = [
      "162.252.136.0/22",
      "12.165.188.0/24",
    ]
  }

  ingress {
    description = "Ping from QL"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"

    cidr_blocks = [
      "162.252.136.0/22",
      "12.165.188.0/24",
      "10.101.0.0/24",
      "10.102.0.0/24",
      "10.121.0.0/24",
      "10.122.0.0/24",
    ]
  }
}

resource "aws_security_group" "Docker_DTR_Nodes" {
  name        = "Docker DTR Nodes"
  description = "Docker DTR Nodes"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    description = "Allow HTTPS"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "162.252.136.0/24",
      "10.153.12.0/22",
      "34.237.27.18/32",
      "12.165.188.0/24",
    ]
  }
}

resource "aws_security_group" "Docker_UCP_Public_ALB" {
  name        = "Docker_UCP_Public_ALB"
  description = "Docker_UCP_Public_ALB"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "162.252.136.0/24",
      "10.153.12.0/22",
      "34.237.27.18/32",
      "12.165.188.0/24",
      "0.0.0.0/0",
    ]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "162.252.136.0/24",
      "10.153.12.0/22",
      "34.237.27.18/32",
      "12.165.188.0/24",
      "0.0.0.0/0",
    ]
  }
}

resource "aws_security_group" "Docker_DTR_Public_ALB" {
  name        = "Docker_DTR_Public_ALB"
  description = "Docker_DTR_Public_ALB"
  vpc_id      = "${aws_vpc.DockerLabVPC.id}"

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "162.252.136.0/24",
      "10.153.12.0/22",
      "34.237.27.18/32",
      "12.165.188.0/24",
      "0.0.0.0/0",
    ]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "162.252.136.0/24",
      "10.153.12.0/22",
      "34.237.27.18/32",
      "12.165.188.0/24",
      "0.0.0.0/0",
    ]
  }
}

#endregion

#region Target Group - UCP External NLB 443

resource "aws_lb_target_group" "Docker_UCP_External_TG_443" {
  name       = "Docker-UCP-External-TG-443"
  port       = "443"
  protocol   = "TCP"
  vpc_id     = "${aws_vpc.DockerLabVPC.id}"
  stickiness = []

  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "10"
    interval            = "30"
  }
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_443_Attach_Master_UCP_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  target_id        = "${aws_instance.Master_UCP_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_443_Attach_Other_UCP_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}

#endregion

#region Target Group - UCP External NLB 6443

resource "aws_lb_target_group" "Docker_UCP_External_TG_6443" {
  name       = "Docker-UCP-External-TG-6443"
  port       = "6443"
  protocol   = "TCP"
  vpc_id     = "${aws_vpc.DockerLabVPC.id}"
  stickiness = []

  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "10"
    interval            = "30"
  }
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_6443_Attach_Master_UCP_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_6443.arn}"
  target_id        = "${aws_instance.Master_UCP_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_6443_Attach_Other_UCP_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_6443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}

#endregion

#region Target Group - DTR External ALB 443

resource "aws_lb_target_group" "Docker_DTR_External_TG_443" {
  name     = "Docker-DTR-External-TG-443"
  port     = "443"
  protocol = "HTTPS"
  vpc_id   = "${aws_vpc.DockerLabVPC.id}"

  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "5"
    interval            = "15"
    matcher             = "200"
  }
}

resource "aws_lb_target_group_attachment" "Docker_DTR_External_TG_443_Attach_Master_DTR_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_DTR_External_TG_443.arn}"
  target_id        = "${aws_instance.Master_DTR_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_DTR_External_TG_443_Attach_Other_DTR_Nodes" {
  count            = 2
  target_group_arn = "${aws_lb_target_group.Docker_DTR_External_TG_443.arn}"
  target_id        = "${element(aws_instance.Other_DTR_Nodes.*.id, count.index)}"
}

/*resource "aws_lb_target_group_attachment" "Docker_DTR_External_TG_443_Attach_Other_DTR_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}*/

#endregion

#region Load Balancer - UCP External NLB

resource "aws_lb" "Docker_UCP_External_LB" {
  name               = "Docker-UCP-External-LB"
  load_balancer_type = "network"
  internal           = false
  subnets            = ["${aws_subnet.az_subnets.*.id}"]

  tags {
    Environment = "Lab"
    Production  = "False"
  }
}

resource "aws_lb_listener" "Docker_UCP_External_LB_443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_External_LB.arn}"
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  }
}

resource "aws_lb_listener" "Docker_UCP_External_LB_6443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_External_LB.arn}"
  port              = "6443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_6443.arn}"
  }
}

#endregion

#region Load Balancer - DTR External ALB

resource "aws_lb" "Docker_DTR_External_LB" {
  name               = "Docker-DTR-External-LB"
  load_balancer_type = "application"
  internal           = false
  subnets            = ["${aws_subnet.az_subnets.*.id}"]

  security_groups = [
    "${aws_security_group.Docker_DTR_Public_ALB.id}",
    "${aws_security_group.egress.id}",
  ]

  tags {
    Environment = "Lab"
    Production  = "False"
  }
}

resource "aws_lb_listener" "Docker_DTR_External_LB_443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_DTR_External_LB.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.DockerLab_DTR_cert.arn}"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_DTR_External_TG_443.arn}"
  }
}

resource "aws_lb_listener" "Docker_DTR_External_LB_80_Listener" {
  load_balancer_arn = "${aws_lb.Docker_DTR_External_LB.arn}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
    target_group_arn = "${aws_lb_target_group.Docker_DTR_External_TG_443.arn}"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

#endregion

#region AMI Grab

data "aws_ami" "rhel_ami" {
  most_recent = true

  filter {
    name   = "name"
    values = ["RHEL-7.5_HVM_GA*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

#endregion

#region S3 stuff

resource "aws_s3_bucket" "dockerlabterratest" {
  bucket        = "dockerlabterratest"
  acl           = "private"
  region        = "${data.aws_region.current.name}"
  force_destroy = true

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Id": "Policy1513202874831",
    "Statement": [
        {
            "Sid": "Stmt1513202825921",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::091936204689:role/DockerLabTerraAssumeRole"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::dockerlabterratest"
        },
        {
            "Sid": "Stmt1513202873250",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::091936204689:role/DockerLabTerraAssumeRole"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::dockerlabterratest/*"
        }
    ]
}
EOF

  tags {
    Name = "dockerlabterratest"
  }
}

#endregion

#region EC2 Instances

resource "random_id" "main_dtr_replica" {
  byte_length = 6

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "Master_UCP_Node" {
  ami                  = "${data.aws_ami.rhel_ami.id}"
  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  tags = {
    Name        = "UCP Manager Node ${count.index + 1}"
    NodeType    = "Manager"
    Environment = "Lab"
    Production  = "false"
  }

  instance_type               = "m4.2xlarge"
  key_name                    = "${var.aws_ssh_key_name}"
  subnet_id                   = "${aws_subnet.az_subnets.*.id[count.index]}"
  associate_public_ip_address = true

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  vpc_security_group_ids = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
    "${aws_security_group.Docker_DTR_Nodes.id}",
  ]

  depends_on = [
    "aws_internet_gateway.DockerLabIG",
    "aws_s3_bucket.dockerlabterratest",
  ]

  lifecycle {
    create_before_destroy = false
  }

  provisioner "file" {
    source      = "${var.telegraf_config_path}"
    destination = "/tmp/telegraf.conf"
  }

  provisioner "file" {
    source      = "${var.docker_license_file_path}"
    destination = "/tmp/license.lic"
  }

  provisioner "file" {
    source      = "${var.ql_root_ca_path}"
    destination = "/tmp/qlrootca.cer"
  }

  provisioner "file" {
    source      = "${var.ql_sub_ca_path}"
    destination = "/tmp/qlsubca.cer"
  }

  provisioner "file" {
    source      = "${var.docker_ucp_cert_path}"
    destination = "/tmp/ucpcert.pem"
  }

  provisioner "file" {
    source      = "${var.docker_ucp_key_path}"
    destination = "/tmp/ucpkey.pem"
  }

  provisioner "file" {
    source      = "${var.daemon_json_path}"
    destination = "/tmp/daemon.json"
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /dev/null /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo docker container create --name dummy-transfer -v ucp-controller-server-certs:/data hello-world
sudo docker cp /tmp/ucpcert.pem dummy-transfer:/data/cert.pem
sudo docker cp /tmp/qlrootca.cer dummy-transfer:/data/ca.pem
sudo docker cp /tmp/ucpkey.pem dummy-transfer:/data/key.pem
sudo mv /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo mv /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
sudo docker swarm init
sudo docker swarm join-token manager -q > /tmp/swarm-manager-token
sudo docker swarm join-token worker -q > /tmp/swarm-worker-token
aws s3 cp /tmp/swarm-manager-token s3://dockerlabterratest/
aws s3 cp /tmp/swarm-worker-token s3://dockerlabterratest/
sudo docker image pull docker/ucp:3.0.5
sudo docker container run --rm --name ucp \
-v /var/run/docker.sock:/var/run/docker.sock \
docker/ucp:3.0.5 install \
--host-address $(docker info -f "{{.Swarm.NodeAddr}}") \
--admin-username ${var.ucp_admin_username} \
--admin-password '${var.ucp_admin_password}' \
--license "$(cat /tmp/license.lic)" \
--external-service-lb ${aws_route53_record.terraucp.name} \
--san ${aws_route53_record.terrainternalucp.name} \
--external-server-cert \
rm -rf /tmp/*
sudo touch /tmp/complete
sudo yum update -y
EOF

  /* removed for testing

*/
  # removed for testing
  # 

  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${aws_instance.Master_UCP_Node.public_ip}"
  }
}

resource "null_resource" "pause" {
  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${aws_instance.Master_UCP_Node.public_ip}"
  }

  provisioner "remote-exec" {
    inline = [
      "while [ ! -f /tmp/complete ]; do sleep 2; done",
    ]
  }
}

resource "aws_instance" "Other_UCP_Nodes" {
  ami                  = "${data.aws_ami.rhel_ami.id}"
  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  count                       = "${var.total_number_of_UCP_nodes - 1}"
  instance_type               = "m4.large"
  key_name                    = "${var.aws_ssh_key_name}"
  subnet_id                   = "${aws_subnet.az_subnets.*.id[count.index]}"
  associate_public_ip_address = true

  tags = {
    Name        = "UCP Manager Node ${count.index + 2}"
    NodeType    = "Manager"
    Environment = "Lab"
    Production  = "false"
  }

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  vpc_security_group_ids = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
    "${aws_security_group.Docker_DTR_Nodes.id}",
  ]

  depends_on = [
    "aws_internet_gateway.DockerLabIG",
    "aws_s3_bucket.dockerlabterratest",
    "aws_instance.Master_UCP_Node",
    "null_resource.pause",
  ]

  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${self.public_ip}"
  }

  lifecycle {
    create_before_destroy = true
  }

  provisioner "file" {
    source      = "${var.telegraf_config_path}"
    destination = "/tmp/telegraf.conf"
  }

  provisioner "file" {
    source      = "${var.ql_root_ca_path}"
    destination = "/tmp/qlrootca.cer"
  }

  provisioner "file" {
    source      = "${var.ql_sub_ca_path}"
    destination = "/tmp/qlsubca.cer"
  }

  provisioner "file" {
    source      = "${var.daemon_json_path}"
    destination = "/tmp/daemon.json"
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /dev/null /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo mv /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo mv /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
aws s3 cp s3://dockerlabterratest/swarm-manager-token /tmp/swarm-manager-token
sudo docker swarm join --token $(echo $(cat /tmp/swarm-manager-token)) ${aws_instance.Master_UCP_Node.private_ip}:2377
sudo yum update -y
EOF
}

resource "aws_instance" "Worker_nodes" {
  ami                  = "${data.aws_ami.rhel_ami.id}"
  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  tags = {
    Name        = "Worker Node ${count.index + 1}"
    NodeType    = "Worker"
    Environment = "Lab"
    Production  = "false"
  }

  count                       = 2
  instance_type               = "m4.large"
  key_name                    = "${var.aws_ssh_key_name}"
  subnet_id                   = "${aws_subnet.az_subnets.*.id[count.index]}"
  associate_public_ip_address = true

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  vpc_security_group_ids = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
    "${aws_security_group.Docker_DTR_Nodes.id}",
  ]

  depends_on = [
    "aws_internet_gateway.DockerLabIG",
    "aws_s3_bucket.dockerlabterratest",
    "aws_instance.Master_UCP_Node",
    "null_resource.pause",
  ]

  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${self.public_ip}"
  }

  lifecycle {
    create_before_destroy = true
  }

  provisioner "file" {
    source      = "${var.telegraf_config_path}"
    destination = "/tmp/telegraf.conf"
  }

  provisioner "file" {
    source      = "${var.ql_root_ca_path}"
    destination = "/tmp/qlrootca.cer"
  }

  provisioner "file" {
    source      = "${var.ql_sub_ca_path}"
    destination = "/tmp/qlsubca.cer"
  }

  provisioner "file" {
    source      = "${var.daemon_json_path}"
    destination = "/tmp/daemon.json"
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo mv /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo mv /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
aws s3 cp s3://dockerlabterratest/swarm-worker-token /tmp/swarm-worker-token
sudo docker swarm join --token $(echo $(cat /tmp/swarm-worker-token)) ${aws_instance.Master_UCP_Node.private_ip}:2377
sudo yum update -y
EOF
}

resource "aws_instance" "Master_DTR_Node" {
  ami                  = "${data.aws_ami.rhel_ami.id}"
  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  tags = {
    Name        = "DTR Node ${count.index + 1}"
    NodeType    = "DTR"
    Environment = "Lab"
    Production  = "false"
  }

  instance_type               = "m4.large"
  key_name                    = "${var.aws_ssh_key_name}"
  subnet_id                   = "${aws_subnet.az_subnets.*.id[count.index]}"
  associate_public_ip_address = true

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  vpc_security_group_ids = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
    "${aws_security_group.Docker_DTR_Nodes.id}",
  ]

  depends_on = [
    "aws_instance.Master_UCP_Node",
    "null_resource.pause",
    "aws_route53_record.terradtr",
    "aws_route53_record.terraucp",
  ]

  lifecycle {
    create_before_destroy = false
  }

  provisioner "file" {
    source      = "${var.telegraf_config_path}"
    destination = "/tmp/telegraf.conf"
  }

  provisioner "file" {
    source      = "${var.docker_license_file_path}"
    destination = "/tmp/license.lic"
  }

  provisioner "file" {
    source      = "${var.ql_root_ca_path}"
    destination = "/tmp/qlrootca.cer"
  }

  provisioner "file" {
    source      = "${var.ql_sub_ca_path}"
    destination = "/tmp/qlsubca.cer"
  }

  provisioner "file" {
    source      = "${var.docker_dtr_cert_path}"
    destination = "/tmp/dtrcert.pem"
  }

  provisioner "file" {
    source      = "${var.docker_dtr_key_path}"
    destination = "/tmp/dtrkey.pem"
  }

  provisioner "file" {
    source      = "${var.daemon_json_path}"
    destination = "/tmp/daemon.json"
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /dev/null /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo cp /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo cp /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
aws s3 cp s3://dockerlabterratest/swarm-worker-token /tmp/swarm-worker-token
sudo docker swarm join --token $(echo $(cat /tmp/swarm-worker-token)) ${aws_instance.Master_UCP_Node.private_ip}:2377
sleep 5m
sudo docker run --rm docker/dtr:2.5.3 \
install \
--dtr-ca "$(cat /tmp/qlrootca.cer)" \
--dtr-cert "$(cat /tmp/dtrcert.pem)" \
--dtr-key "$(cat /tmp/dtrkey.pem)" \
--dtr-external-url https://${aws_route53_record.terradtr.name} \
--ucp-ca "$(cat /tmp/qlrootca.cer)" \
--ucp-node $(echo $HOSTNAME) \
--ucp-password '${var.ucp_admin_password}' \
--ucp-username ${var.ucp_admin_username} \
--ucp-url https://${aws_route53_record.terraucp.name} \
--replica-id "${random_id.main_dtr_replica.hex}"
touch /tmp/complete
sudo yum update -y
EOF

  /* removed for testing

*/
  # removed for testing
  # 

  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${aws_instance.Master_DTR_Node.public_ip}"
  }
}

resource "null_resource" "pause_dtr" {
  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${aws_instance.Master_DTR_Node.public_ip}"
  }

  provisioner "remote-exec" {
    inline = [
      "while [ ! -f /tmp/complete ]; do sleep 2; done",
    ]
  }
}

resource "aws_instance" "Other_DTR_Nodes" {
  count                = 2
  ami                  = "${data.aws_ami.rhel_ami.id}"
  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  tags = {
    Name        = "DTR Node ${count.index + 2}"
    NodeType    = "DTR"
    Environment = "Lab"
    Production  = "false"
  }

  instance_type               = "m4.large"
  key_name                    = "${var.aws_ssh_key_name}"
  subnet_id                   = "${aws_subnet.az_subnets.*.id[count.index]}"
  associate_public_ip_address = true

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  vpc_security_group_ids = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
    "${aws_security_group.Docker_DTR_Nodes.id}",
  ]

  depends_on = [
    "aws_instance.Master_UCP_Node",
    "null_resource.pause",
    "aws_instance.Master_DTR_Node",
    "null_resource.pause_dtr",
  ]

  lifecycle {
    create_before_destroy = false
  }

  connection {
    user        = "ec2-user"
    private_key = "${file(var.aws_ssh_key_path)}"
    host        = "${self.public_ip}"
  }

  provisioner "file" {
    source      = "${var.telegraf_config_path}"
    destination = "/tmp/telegraf.conf"
  }

  provisioner "file" {
    source      = "${var.docker_license_file_path}"
    destination = "/tmp/license.lic"
  }

  provisioner "file" {
    source      = "${var.ql_root_ca_path}"
    destination = "/tmp/qlrootca.cer"
  }

  provisioner "file" {
    source      = "${var.ql_sub_ca_path}"
    destination = "/tmp/qlsubca.cer"
  }

  provisioner "file" {
    source      = "${var.docker_dtr_cert_path}"
    destination = "/tmp/dtrcert.pem"
  }

  provisioner "file" {
    source      = "${var.docker_dtr_key_path}"
    destination = "/tmp/dtrkey.pem"
  }

  provisioner "file" {
    source      = "${var.daemon_json_path}"
    destination = "/tmp/daemon.json"
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /dev/null /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo cp /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo cp /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
aws s3 cp s3://dockerlabterratest/swarm-worker-token /tmp/swarm-worker-token
sudo docker swarm join --token $(echo $(cat /tmp/swarm-worker-token)) ${aws_instance.Master_UCP_Node.private_ip}:2377
sleep ${((count.index + 1) * 3) + 5}m
sudo docker run --rm docker/dtr:2.5.3 \
join \
--existing-replica-id "${random_id.main_dtr_replica.hex}" \
--ucp-ca "$(cat /tmp/qlrootca.cer)" \
--ucp-node $(echo $HOSTNAME) \
--ucp-password '${var.ucp_admin_password}' \
--ucp-username ${var.ucp_admin_username} \
--ucp-url https://${aws_route53_record.terraucp.name}
touch /tmp/complete
sudo yum update -y
EOF
}

#endregion

#region ASG Stuff

resource "aws_launch_configuration" "RHEL_Worker_Node_Configuration" {
  name_prefix                 = "RHEL-Worker-Node-Configuration-"
  image_id                    = "${data.aws_ami.rhel_ami.id}"
  key_name                    = "${var.aws_ssh_key_name}"
  instance_type               = "m4.large"
  associate_public_ip_address = true
  ebs_optimized               = true

  root_block_device = {
    volume_size = 100
    volume_type = "gp2"
  }

  iam_instance_profile = "${aws_iam_instance_profile.DockerLabTerraInstanceProfile.id}"

  security_groups = [
    "${aws_security_group.From_QL_Public.id}",
    "${aws_security_group.egress.id}",
    "${aws_security_group.QL_On_Prem.id}",
    "${aws_security_group.Docker_Linux_Nodes.id}",
  ]

  lifecycle {
    create_before_destroy = true
  }

  user_data = <<EOF
#!/bin/bash
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo yum install python-pip -y
sudo pip install --upgrade pip
sudo pip install awscli
export DOCKERURL="${var.docker_ee_repo}"
sudo -E sh -c 'echo "$DOCKERURL/rhel" > /etc/yum/vars/dockerurl'
sudo sh -c 'echo "7" > /etc/yum/vars/dockerosversion'
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --enable rhel-7-server-extras-rpms
sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
sudo -E yum-config-manager --add-repo "$DOCKERURL/rhel/docker-ee.repo"
sudo yum -y install docker-ee
sudo systemctl start docker
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo yum install -y wget bind-utils
wget https://dl.influxdata.com/telegraf/releases/telegraf-1.4.5-1.x86_64.rpm
sudo yum install -q -y telegraf-1.4.5-1.x86_64.rpm
sudo mv /tmp/daemon.json /etc/docker/daemon.json
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.orig
sudo mv /tmp/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl start telegraf
sudo systemctl enable telegraf
install -Dv /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
cat /tmp/qlrootca.cer > /etc/docker/certs.d/terradtr.dockersandbox.foc.zone:443/ca.crt
sudo mv /tmp/qlsubca.cer /etc/pki/ca-trust/source/anchors/qlsubca.cer
sudo mv /tmp/qlrootca.cer /etc/pki/ca-trust/source/anchors/qlrootca.cer
sudo update-ca-trust enable;sudo update-ca-trust extract
sudo usermod -aG docker telegraf;sudo systemctl restart telegraf
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/overlay
sudo systemctl start docker
aws s3 cp s3://dockerlabterratest/swarm-worker-token /tmp/swarm-worker-token
sudo docker swarm join --token $(echo $(cat /tmp/swarm-worker-token)) ${aws_instance.Master_UCP_Node.private_ip}:2377
sudo yum update -y
EOF
}

resource "aws_autoscaling_group" "RHEL_Worker_Node_ASG" {
  name_prefix          = "RHEL-Worker-Node-ASG-"
  launch_configuration = "${aws_launch_configuration.RHEL_Worker_Node_Configuration.name}"
  health_check_type   = "EC2"
  vpc_zone_identifier = ["${aws_subnet.az_subnets.*.id}"]
  min_size                  = 3
  max_size                  = 10
  default_cooldown          = 3600
  health_check_grace_period = 300
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Name"
      value               = "ASG Worker Node"
      propagate_at_launch = true
    },
  ]


  initial_lifecycle_hook {
    name                    = "TerraSwarmLeave"
    default_result          = "CONTINUE"
    heartbeat_timeout       = 60
    lifecycle_transition    = "autoscaling:EC2_INSTANCE_TERMINATING"
    notification_target_arn = "${aws_sns_topic.Terra_ASG_Worker_Termination.arn}"
    role_arn                = "${aws_iam_role.Terra_SNS_Role.arn}"
  }


  termination_policies = [
    "OldestInstance",
    "OldestLaunchConfiguration",
  ]


  lifecycle {
    create_before_destroy = true
  }
}

#endregion

#region SNS Stuff

resource "aws_sns_topic" "Terra_ASG_Worker_Termination" {
  name = "Terra-Worker-Termination"
}

resource "aws_sns_topic_subscription" "Terra_ASG_Worker_Termination_Lambda" {
  topic_arn = "${aws_sns_topic.Terra_ASG_Worker_Termination.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.ASG_Lifecycle_Swarm_Leave.arn}"
}

#endregion

#region Lambda stuff

resource "aws_lambda_function" "ASG_Lifecycle_Swarm_Leave" {
  filename         = "${var.lambda_payload_path}"
  function_name    = "ASG_Lifecycle_Swarm_Leave"
  role             = "${aws_iam_role.Terra_Lambda_Role.arn}"
  handler          = "payload.lambda_handler"
  runtime          = "python3.6"
  timeout = 30
}

#endregion



#region Outputs

output "Node_IP_Adresses" {
  value = [
    "${aws_instance.Master_UCP_Node.*.public_ip}",
    "${aws_instance.Other_UCP_Nodes.*.public_ip}",
    "${aws_instance.Worker_nodes.*.public_ip}",
  ]
}

#endregion


/* Old LB and TG stuff, keeping for reference
#region Target Group - UCP External ALB 443

resource "aws_lb_target_group" "Docker_UCP_External_TG_443" {
  name     = "Docker-UCP-External-TG-443"
  port     = "443"
  protocol = "HTTPS"
  vpc_id   = "${aws_vpc.DockerLabVPC.id}"

  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "5"
    interval            = "15"
    matcher             = "200"
  }
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_443_Attach_Master_UCP_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  target_id        = "${aws_instance.Master_UCP_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_UCP_External_TG_443_Attach_Other_UCP_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}

#endregion
#region Target Group - UCP Internal NLB 443

resource "aws_lb_target_group" "Docker_UCP_Internal_TG_443" {
  name     = "Docker-UCP-Internal-TG-443"
  port     = "443"
  protocol = "TCP"
  vpc_id   = "${aws_vpc.DockerLabVPC.id}"
  stickiness = []
  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "10"
    interval            = "30"
  }
}
resource "aws_lb_target_group_attachment" "Docker_UCP_Internal_TG_443_Attach_Master_UCP_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_443.arn}"
  target_id        = "${aws_instance.Master_UCP_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_UCP_Internal_TG_443_Attach_Other_UCP_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}

#endregion
#region Target Group - UCP Internal NLB 6443

resource "aws_lb_target_group" "Docker_UCP_Internal_TG_6443" {
  name     = "Docker-UCP-Internal-TG-6443"
  port     = "6443"
  protocol = "TCP"
  vpc_id   = "${aws_vpc.DockerLabVPC.id}"
  stickiness = []
  health_check = {
    protocol            = "HTTPS"
    path                = "/_ping"
    port                = "443"
    healthy_threshold   = "3"
    unhealthy_threshold = "3"
    timeout             = "10"
    interval            = "30"
  }
}
resource "aws_lb_target_group_attachment" "Docker_UCP_Internal_TG_6443_Attach_Master_UCP_Node" {
  target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_6443.arn}"
  target_id        = "${aws_instance.Master_UCP_Node.id}"
}

resource "aws_lb_target_group_attachment" "Docker_UCP_Internal_TG_6443_Attach_Other_UCP_Nodes" {
  count            = "${var.total_number_of_UCP_nodes - 1}"
  target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_6443.arn}"
  target_id        = "${element(aws_instance.Other_UCP_Nodes.*.id, count.index)}"
}

#endregion
#region Load Balancer - UCP External ALB

resource "aws_lb" "Docker_UCP_External_LB" {
  name               = "Docker-UCP-External-LB"
  load_balancer_type = "application"
  internal           = false
  subnets            = ["${aws_subnet.az_subnets.*.id}"]
  security_groups    = [
    "${aws_security_group.Docker_UCP_Public_ALB.id}",
    "${aws_security_group.egress.id}"
  ]

  tags {
    Environment = "Lab"
    Production  = "False"
  }
}

resource "aws_lb_listener" "Docker_UCP_External_LB_443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_External_LB.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_iam_server_certificate.DockerLab_UCP_cert.arn}"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"
  }
}

resource "aws_lb_listener" "Docker_UCP_External_LB_80_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_External_LB.arn}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_External_TG_443.arn}"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

#endregion
#region Load Balancer - UCP Internal NLB

resource "aws_lb" "Docker_UCP_Internal_LB" {
  name = "Docker-UCP-Internal-LB"
  load_balancer_type = "network"
  internal = true
  subnets = ["${aws_subnet.az_subnets.*.id}"]
  tags {
    Environment = "Lab"
    Production  = "False"
  }
}

resource "aws_lb_listener" "Docker_UCP_Internal_LB_443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_Internal_LB.arn}"
  port              = "443"
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_443.arn}"
  }
}
resource "aws_lb_listener" "Docker_UCP_Internal_LB_6443_Listener" {
  load_balancer_arn = "${aws_lb.Docker_UCP_Internal_LB.arn}"
  port              = "6443"
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.Docker_UCP_Internal_TG_6443.arn}"
  }
}

#endregion
*/
