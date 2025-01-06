from aws_cdk import (
    # Duration,
    Stack,
    # aws_sqs as sqs,
    CfnOutput,
    Tags,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_eks as eks,
)
from constructs import Construct
from typing import List

class EksAutoModeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create VPC for Amazon EKS cluster
        vpc = ec2.Vpc(
            self, "EKSAutoModeVPC", 
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                )
            ],
            nat_gateways=1  # Use 1 NAT Gateway to save cost - don't use in production!
        )

        # Add tags to VPC subnets to enable Load Balancers
        for subnet in vpc.public_subnets:
            Tags.of(subnet).add("kubernetes.io/role/elb", "1")
        
        for subnet in vpc.private_subnets:
            Tags.of(subnet).add("kubernetes.io/role/internal-elb", "1")
        
        # Create cluster IAM role for the cluster
        cluster_role = iam.Role(
            self, "EKSAutoModeClusterRole",
            assumed_by=iam.ServicePrincipal("eks.amazonaws.com"),  # Basic trust relationship
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSComputePolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSBlockStoragePolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSLoadBalancingPolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSNetworkingPolicy")
            ]
        )
        
        # Modify the trust policy to include sts:TagSession
        cluster_role.assume_role_policy.add_statements(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sts:TagSession"],
                principals=[iam.ServicePrincipal("eks.amazonaws.com")]
            )
        )

        # Create IAM Role for EKS nodes
        node_role = iam.Role(
            self, "EKSAutoModeNodeRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodeMinimalPolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPullOnly")
            ]
        )

        # Create EKS Cluster with Auto Mode
        cluster = eks.CfnCluster(
            self, "EKSAutoModeCluster",
            version="1.31",
            # Enable EKS Auto Mode compute config
            compute_config=eks.CfnCluster.ComputeConfigProperty(
                enabled=True,
                node_pools=["system", "general-purpose"],
                node_role_arn=node_role.role_arn
            ),
            # Enable load balancing capability
            kubernetes_network_config=eks.CfnCluster.KubernetesNetworkConfigProperty(
                elastic_load_balancing=eks.CfnCluster.ElasticLoadBalancingProperty(
                    enabled=True
                ),
                ip_family="ipv4"
            ),
            # Enable storage config
            storage_config=eks.CfnCluster.StorageConfigProperty(
                block_storage=eks.CfnCluster.BlockStorageProperty(
                    enabled=True
                )
            ),
            # VPC configuration
            resources_vpc_config=eks.CfnCluster.ResourcesVpcConfigProperty(
                subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets],
                endpoint_private_access=True,
                endpoint_public_access=True
            ),
            role_arn=cluster_role.role_arn,
            # Access configuration
            access_config=eks.CfnCluster.AccessConfigProperty(
                authentication_mode="API",
                bootstrap_cluster_creator_admin_permissions=False
            ),
            
            # Upgrade policy
            upgrade_policy=eks.CfnCluster.UpgradePolicyProperty(
                support_type="STANDARD"
            )
        )

        # Create cluster admin access entry
        admin_access = eks.CfnAccessEntry(
            self, "EKSAutoModeClusterRoleAccessEntry",
            cluster_name=cluster.ref,
            principal_arn=f"arn:aws:iam::{self.account}:role/Admin",
            access_policies=[
                eks.CfnAccessEntry.AccessPolicyProperty(
                    access_scope=eks.CfnAccessEntry.AccessScopeProperty(
                        type="cluster"
                    ),
                    policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                )
            ]
        )

        # Add output for kubeconfig command
        CfnOutput(
            self, "KubeconfigCommand",
            value=f"aws eks --region {self.region} update-kubeconfig --name {cluster.ref}",
            description="Command to update kubeconfig"
        )
