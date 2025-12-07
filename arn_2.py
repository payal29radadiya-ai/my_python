import argparse
import boto3
import json
import logging
import yaml
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_yaml(file_path):
    """Load and parse the YAML file."""
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Error loading YAML file: {e}")
        raise

def get_arn_resource_type(arn):
    """Extract the resource type from ARN."""
    # ARN format: arn:aws:service:region:account:resource
    parts = arn.split(':')
    if len(parts) >= 6:
        return parts[2], parts[5]  # service, resource
    return None, None

def check_RDSAuroraPostgres(component, region, account_id):
    """Check status of ARNs for RDSAuroraPostgres component by querying AWS."""
    client = boto3.client('rds', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'rds' and 'cluster' in resource:
            cluster_id = resource.split('/')[-1] if '/' in resource else resource
            try:
                response = client.describe_db_clusters(DBClusterIdentifier=cluster_id)
                status = response['DBClusters'][0]['Status']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Cluster status: {status}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        elif service == 'ec2' and 'security-group' in resource:
            sg_id = resource.split('/')[-1]
            ec2_client = boto3.client('ec2', region_name=region)
            try:
                response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                statuses.append({"arn": arn, "status": "SUCCESS", "message": "Security group exists"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        elif service == 'backup' and 'recovery-point' in resource:
            backup_client = boto3.client('backup', region_name=region)
            try:
                response = backup_client.describe_recovery_point(BackupVaultName='default', RecoveryPointArn=arn)
                statuses.append({"arn": arn, "status": "SUCCESS", "message": "Recovery point exists"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_KMS(component, region, account_id):
    """Check status of ARNs for KMS component by querying AWS."""
    client = boto3.client('kms', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'kms':
            key_id = resource.split('/')[-1] if '/' in resource else resource
            try:
                response = client.describe_key(KeyId=key_id)
                state = response['KeyMetadata']['KeyState']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Key state: {state}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_ManagementHost(component, region, account_id):
    """Check status of ARNs for ManagementHost component by querying AWS."""
    ec2_client = boto3.client('ec2', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'ec2' and 'instance' in resource:
            instance_id = resource.split('/')[-1]
            try:
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                state = response['Reservations'][0]['Instances'][0]['State']['Name']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Instance state: {state}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_SQS(component, region, account_id):
    """Check status of ARNs for SQS component by querying AWS."""
    client = boto3.client('sqs', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'sqs':
            queue_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{resource.split('/')[-1]}"
            try:
                response = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
                statuses.append({"arn": arn, "status": "SUCCESS", "message": "Queue exists and accessible"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_GlobalRoles(component, region, account_id):
    """Check status of ARNs for GlobalRoles component by querying AWS."""
    iam_client = boto3.client('iam')
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'iam' and 'role' in resource:
            role_name = resource.split('/')[-1]
            try:
                response = iam_client.get_role(RoleName=role_name)
                statuses.append({"arn": arn, "status": "SUCCESS", "message": "Role exists"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_Roles(component, region, account_id):
    """Check status of ARNs for Roles component by querying AWS."""
    return check_GlobalRoles(component, region, account_id)

def check_Route53Record(component, region, account_id):
    """Check status of ARNs for Route53Record component by querying AWS."""
    client = boto3.client('route53')
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'route53':
            hosted_zone_id = resource.split('/')[-1]
            try:
                response = client.get_hosted_zone(Id=hosted_zone_id)
                statuses.append({"arn": arn, "status": "SUCCESS", "message": "Hosted zone exists"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_NetworkLoadBalancer(component, region, account_id):
    """Check status of ARNs for NetworkLoadBalancer component by querying AWS."""
    elb_client = boto3.client('elbv2', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'elasticloadbalancing':
            lb_arn = arn
            try:
                response = elb_client.describe_load_balancers(LoadBalancerArns=[lb_arn])
                state = response['LoadBalancers'][0]['State']['Code']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Load balancer state: {state}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_ApplicationLoadBalancer(component, region, account_id):
    """Check status of ARNs for ApplicationLoadBalancer component by querying AWS."""
    return check_NetworkLoadBalancer(component, region, account_id)

def check_ECSCluster(component, region, account_id):
    """Check status of ARNs for ECSCluster component by querying AWS."""
    client = boto3.client('ecs', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'ecs' and 'cluster' in resource:
            cluster_name = resource.split('/')[-1]
            try:
                response = client.describe_clusters(clusters=[cluster_name])
                status = response['clusters'][0]['status']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Cluster status: {status}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def check_Lambda(component, region, account_id):
    """Check status of ARNs for Lambda component by querying AWS."""
    client = boto3.client('lambda', region_name=region)
    statuses = []
    for arn in component.get('tfModules', [{}])[0].get('arns', []):
        service, resource = get_arn_resource_type(arn)
        if service == 'lambda':
            function_name = resource.split(':')[-1] if ':' in resource else resource
            try:
                response = client.get_function(FunctionName=function_name)
                state = response['Configuration']['State']
                statuses.append({"arn": arn, "status": "SUCCESS", "message": f"Function state: {state}"})
            except ClientError as e:
                statuses.append({"arn": arn, "status": "FAILED", "message": str(e)})
        else:
            statuses.append({"arn": arn, "status": "UNKNOWN", "message": "Unsupported ARN type"})
    return statuses

def main():
    parser = argparse.ArgumentParser(description="Check ARN statuses for AWS components from YAML file by querying AWS.")
    parser.add_argument('-f', '--yaml_file', required=True, help='Path to the YAML file')
    parser.add_argument('--log_file', required=True, help='Path to the log file')
    args = parser.parse_args()

    # Set up file logging
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(file_handler)

    try:
        data = load_yaml(args.yaml_file)
        deployment = data.get('deployment', {})
        environment = deployment.get('Environment', {})
        region = environment.get('awsRegion')
        account_id = environment.get('awsAccountID')
        components = deployment.get('components', [])

        component_functions = {
            'RDSAuroraPostgres': check_RDSAuroraPostgres,
            'KMS': check_KMS,
            'ManagementHost': check_ManagementHost,
            'SQS': check_SQS,
            'GlobalRoles': check_GlobalRoles,
            'Roles': check_Roles,
            'Route53Record': check_Route53Record,
            'NetworkLoadBalancer': check_NetworkLoadBalancer,
            'ApplicationLoadBalancer': check_ApplicationLoadBalancer,
            'ECSCluster': check_ECSCluster,
            'Lambda': check_Lambda
        }

        updated_components = []
        overall_status = "SUCCESS"
        messages = []

        for component in components:
            comp_type = component.get('componentType')
            comp_name = component.get('componentName')
            if comp_type in component_functions:
                try:
                    statuses = component_functions[comp_type](component, region, account_id)
                    component['arn_statuses'] = statuses
                    for status in statuses:
                        if status['status'] != 'SUCCESS':
                            overall_status = "FAILED"
                            messages.append(f"{comp_type} {comp_name}: {status['message']}")
                except Exception as e:
                    logging.error(f"Error checking {comp_type} {comp_name}: {e}")
                    overall_status = "FAILED"
                    messages.append(f"Error checking {comp_type} {comp_name}: {str(e)}")
            else:
                logging.warning(f"No function for component type: {comp_type}")
                messages.append(f"No check function for {comp_type}")
            updated_components.append(component)

        output = {
            "status": overall_status,
            "message": "; ".join(messages) if messages else "All ARN health checks passed",
            "data": {
                "deployment": {
                    "sealID": deployment.get('sealID'),
                    "modelName": deployment.get('modelName'),
                    "modelVersion": deployment.get('modelVersion'),
                    "deploymentName": deployment.get('deploymentName'),
                    "Environment": environment,
                    "components": updated_components
                }
            }
        }

        print(json.dumps(output, indent=2))

    except NoCredentialsError:
        logging.error("AWS credentials not found. Please configure AWS credentials.")
        print(json.dumps({"status": "FAILED", "message": "AWS credentials not found", "data": {}}))
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(json.dumps({"status": "FAILED", "message": str(e), "data": {}}))

if __name__ == "__main__":
    main()
