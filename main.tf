################################################################################
# Data
################################################################################

locals {
  name        = "mx-test-eks-01"
  region      = "us-east-2"
  profile     = "eks-admin"
  tgw_id      = "tgw-0278ef42d6c498bdd"
  domain_name = "wlabs.cloud"
  postgres_ver = "16.1"
  s3_bucket_name = "${local.name}-storage"
  environments_internal_names = ["global"]

  vpc_cidr          = "172.19.0.0/16"
  azs               = slice(data.aws_availability_zones.available.names, 0, 3)
  my_cidr           = "192.168.0.0/16"
  route_53_zone_arn = "arn:aws:route53:::hostedzone/Z09104732JMA6AZ8SB4JI"

  tags = {
    Blueprint = local.name
  }
}

provider "aws" {
  region  = local.region
  profile = local.profile
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

data "aws_availability_zones" "available" {}

################################################################################
# Cluster
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = local.name
  cluster_version = "1.29"

  enable_irsa                              = true
  enable_cluster_creator_admin_permissions = true

  cluster_security_group_additional_rules = {
    https_ingress_from_my_cidr = {
      description = "Allow HTTPS from 192.168.0.0/16"
      from_port   = 443
      to_port     = 443
      type        = "ingress"
      protocol    = "tcp"
      cidr_blocks = [local.my_cidr]
    }
    ssh_ingress_from_my_cidr = {
      description = "Allow HTTPS from 192.168.0.0/16"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      type        = "ingress"
      cidr_blocks = [local.my_cidr]
    }
  }

  vpc_id                     = module.vpc.vpc_id
  subnet_ids                 = module.vpc.private_subnets
  create_node_security_group = false
  eks_managed_node_groups = {
    launch_template = {
      use_custom_launch_template = true
      id  = aws_launch_template.eks_launch_template.id
      version = "$Latest"
      instance_types =["m5.large"]
      desired_size = 3
      max_size     = 3
      min_size     = 1
    }
  }
  

  tags = local.tags
  depends_on = [aws_ec2_transit_gateway_vpc_attachment.tgw_vpc_attachment, aws_route.private_subnet_to_tgw]
}

module "eks_blueprints_kubernetes_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.16.3"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  oidc_provider_arn = module.eks.oidc_provider_arn
  cluster_version   = module.eks.cluster_version

  eks_addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni    = {}
  }

  enable_aws_load_balancer_controller = true
  enable_cert_manager = true
  enable_external_dns = true
  external_dns = {
    name          = "external-dns"
    chart_version = "1.12.2"
    repository    = "https://kubernetes-sigs.github.io/external-dns/"
    namespace     = "external-dns"
    values        = [templatefile("${path.module}/templates/external-dns.yaml", {
      hostname = local.domain_name
    })]
  }
  external_dns_route53_zone_arns = [local.route_53_zone_arn]
  enable_ingress_nginx = true
  ingress_nginx = {
    name = "ingress-nginx-internal"
    values = [
      <<-EOT
          controller:
            replicaCount: 3
            service:
              annotations:
                service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
                service.beta.kubernetes.io/aws-load-balancer-scheme: internal
                service.beta.kubernetes.io/aws-load-balancer-security-groups: ${aws_security_group.ingress_nginx_internal.id}
                service.beta.kubernetes.io/aws-load-balancer-manage-backend-security-group-rules: true
              loadBalancerClass: service.k8s.aws/nlb
            topologySpreadConstraints:
              - maxSkew: 1
                topologyKey: topology.kubernetes.io/zone
                whenUnsatisfiable: ScheduleAnyway
                labelSelector:
                  matchLabels:
                    app.kubernetes.io/instance: ingress-nginx-internal
              - maxSkew: 1
                topologyKey: kubernetes.io/hostname
                whenUnsatisfiable: ScheduleAnyway
                labelSelector:
                  matchLabels:
                    app.kubernetes.io/instance: ingress-nginx-internal
            minAvailable: 2
            ingressClassResource:
              name: ingress-nginx-internal
              default: false
        EOT
    ]
  }

  depends_on = [module.eks]
}

module "ebs_csi_driver_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.20"

  role_name_prefix = "${module.eks.cluster_name}-ebs-csi-driver-"

  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

################################################################################
# Supporting Resources
################################################################################

resource "aws_security_group" "ingress_nginx_internal" {
  name        = "ingress-nginx-internal"
  description = "Allow local HTTP and HTTPS traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.my_cidr, local.vpc_cidr] # modify to your requirements
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.my_cidr, local.vpc_cidr] # modify to your requirements
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_route" "private_subnet_to_tgw" {
  count = length(module.vpc.private_route_table_ids)

  route_table_id         = module.vpc.private_route_table_ids[count.index]
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = local.tgw_id
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  manage_default_vpc = false

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]

  enable_nat_gateway = false

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}

module "vpc_endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "~> 5.1"

  vpc_id = module.vpc.vpc_id

  # Security group
  create_security_group      = true
  security_group_name_prefix = "${local.name}-vpc-endpoints-"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  endpoints = merge({
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = module.vpc.private_route_table_ids
      tags = {
        Name = "${local.name}-s3"
      }
    }
    },
    { for service in toset(["autoscaling", "ecr.api", "ecr.dkr", "ec2", "ec2messages", "elasticloadbalancing", "sts", "kms", "logs", "ssm", "ssmmessages"]) :
      replace(service, ".", "_") =>
      {
        service             = service
        subnet_ids          = module.vpc.private_subnets
        private_dns_enabled = true
        tags                = { Name = "${local.name}-${service}" }
      }
  })

  tags = local.tags
}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_vpc_attachment" {
  transit_gateway_id = local.tgw_id
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnets

  tags = local.tags
}

resource "kubernetes_config_map" "registry_certificate" {
  metadata {
    name      = "registry-certificate"
    namespace = "kube-system"
  }

  data = {
    "registry.crt" = filebase64("/Users/ronban/Downloads/custom.crt")
  }
}

data "aws_ami" "eks" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amazon-eks-node-*"]
  }

  filter {
    name   = "owner-id"
    values = ["602401143452"] # Amazon's official EKS AMI account ID
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_launch_template" "eks_launch_template" {
  name_prefix   = "${local.name}-"
  image_id      = data.aws_ami.eks.id
  instance_type = "m5.large"

  user_data = base64encode(<<-EOF
    #!/bin/bash
    /etc/eks/bootstrap.sh ${local.name}

    # Create directory for the registry certificates
    mkdir -p /etc/docker/certs.d/c.wlabs.cloud

    # Add the registry certificate from the ConfigMap
    kubectl get configmap registry-certificate -n kube-system -o jsonpath="{.data['registry.crt']}" | base64 -d > /etc/docker/certs.d/c.wlabs.cloud/ca.crt

    # Restart docker to apply the certificate
    systemctl restart docker
  EOF
  )
}

module "file_storage" {
  source         = "./modules/file-storage"
  s3_bucket_name = local.s3_bucket_name
}

module "databases" {
  for_each = toset(local.environments_internal_names)
  source                            = "./modules/databases"
  identifier                        = "${local.name}-database-${each.key}"
  subnets                           = module.vpc.private_subnets
  postgres_version                  = local.postgres_ver
  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
}

resource "aws_iam_policy" "environment_policy" {
  name        = "${local.name}-env-policy"
  description = "Environment Template Policy"

  policy = templatefile("${path.module}/iam-templates/iam_environment_policy.json.tpl", {
    aws_region                     = local.region
    aws_account_id                 = data.aws_caller_identity.current.account_id
    db_instance_resource_ids       = [for value in values(module.databases) : tostring(value.database_resource_id[0])]
    filestorage_shared_bucket_name = local.s3_bucket_name
  })
}

resource "aws_iam_policy" "provisioner_policy" {
  name        = "${local.name}-provisioner-policy"
  description = "Storage Provisioner admin Policy"

  policy = templatefile("${path.module}/iam-templates/iam_provisioner_policy.json.tpl", {
    aws_region                     = local.region
    aws_account_id                 = data.aws_caller_identity.current.account_id
    db_instance_resource_ids       = [for value in values(module.databases) : tostring(value.database_resource_id[0])]
    db_instance_usernames          = [for value in values(module.databases) : tostring(value.database_username[0])]
    filestorage_shared_bucket_name = local.s3_bucket_name
    environment_policy_arn         = aws_iam_policy.environment_policy.arn
  })
}

resource "aws_iam_role" "storage_provisioner_role" {
  name        = "${local.name}-storage-provisioner-irsa"
  description = "Storage Provisioner admin Policy"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${module.eks.oidc_provider}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.eks.oidc_provider}:aud" : "sts.amazonaws.com",
            "${module.eks.oidc_provider}:sub" : "system:serviceaccount:mendix:mendix-storage-provisioner"
          }
        }
      }
    ]
  })

  managed_policy_arns = [aws_iam_policy.provisioner_policy.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_ebs_encryption_by_default" "ebs_encryption" {
  enabled = true
}

