namespaceID: "${namespace_id}"
namespaceSecret: "${namespace_secret}"
mendixOperatorVersion: "${mendix_operator_version}"
awsRegion: "${aws_region}"
certificateExpirationEmail: "${certificate_expiration_email}"
registry:
    type: generic
    generic_registry:
        auth_pull_url: "${registry_pullurl}"
        auth_push_url: "${registry_pullurl}"
        registry_name: "${registry_repository}"
        enable_auth: true
        auth_user: "${registry_repository_username}"
        auth_password: "${registry_repository_password}"
        link_secret_to_service_account: true
ingress:
    className: "nginx"
    domainName: "${ingress_domainname}"
database_plans:
%{ for index, address in database_server_addresses ~}
    - name: "pg-${environments_internal_names[index]}"
      host: "${address}"
      aws_iam_role: "${storage_provisioner_iam_admin_role}"
      kubernetes_service_account: mendix-storage-provisioner
      port: "${database_ports[index]}"
      user: "${database_usernames[index]}"
      db_name: "${database_names[index]}"
      master_password: "${database_passwords[index]}"
%{ endfor ~}
storage_plan:
    existing_bucket: "${s3_bucket_name}"
    existing_policy: "${environment_iam_template_policy}"
    admin_iam_role: "${storage_provisioner_iam_admin_role}"
    oidc_url: "${oidc_url}"
    kubernetes_service_account: mendix-storage-provisioner
environmentsInternalNames:
%{ for name in environments_internal_names ~}
    - ${name}
%{ endfor ~}
clusterName: "${cluster_name}"
accountID: "${account_id}"