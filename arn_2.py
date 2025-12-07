import yaml
import json
import boto3
import logging
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
import re

# ------------------------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------------------------
logging.basicConfig(
    filename="arn_metadata_health_check.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# PARSE ARN
# ------------------------------------------------------------------------------
def parse_arn(arn: str):
    """
    Parse ARN into components.
    Example ARN Format:
      arn:aws:rds:us-east-1:111122223333:cluster:mydbcluster
    """
    try:
        parts = arn.split(':', 5)
        return {
            "partition": parts[1],
            "service": parts[2],
            "region": parts[3],
            "account": parts[4],
            "resource": parts[5]
        }
    except Exception as e:
        logger.error(f"Invalid ARN format: {arn}")
        return None

# ------------------------------------------------------------------------------
# AWS METADATA GETTERS FOR EACH SERVICE
# ------------------------------------------------------------------------------

def get_rds_metadata(parsed):
    client = boto3.client("rds", region_name=parsed["region"])
    resource = parsed["resource"]

    if resource.startswith("cluster:"):
        cluster = resource.split(":", 1)[1]
        return client.describe_db_clusters(DBClusterIdentifier=cluster)

    if resource.startswith("cluster-snapshot:"):
        snap = resource.split(":", 1)[1]
        return client.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap)

    if resource.startswith("db:"):
        db = resource.split(":", 1)[1]
        return client.describe_db_instances(DBInstanceIdentifier=db)

    raise Exception("Unsupported RDS ARN resource type")

def get_ec2_metadata(parsed):
    client = boto3.client("ec2", region_name=parsed["region"])
    resource = parsed["resource"]

    if resource.startswith("security-group/"):
        sg_id = resource.split("/")[1]
        return client.describe_security_groups(GroupIds=[sg_id])

    return {"status": "UNKNOWN_EC2_RESOURCE"}

def get_kms_metadata(parsed):
    client = boto3.client("kms", region_name=parsed["region"])
    return client.describe_key(KeyId=f"arn:{parsed['partition']}:kms:{parsed['region']}:{parsed['account']}:{parsed['resource']}")

def get_sqs_metadata(parsed):
    queue_name = parsed["resource"]
    queue_url = f"https://sqs.{parsed['region']}.amazonaws.com/{parsed['account']}/{queue_name}"
    client = boto3.client("sqs", region_name=parsed["region"])
    return client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])

def get_lambda_metadata(parsed):
    function_name = parsed["resource"].split(":")[-1]
    client = boto3.client("lambda", region_name=parsed["region"])
    return client.get_function(FunctionName=function_name)

def get_iam_metadata(parsed):
    client = boto3.client("iam")
    resource = parsed["resource"]

    if resource.startswith("role/"):
        role = resource.split("/")[1]
        return client.get_role(RoleName=role)

    if resource.startswith("policy/"):
        policy = resource.split("/")[1]
        return client.get_policy(PolicyArn=f"arn:aws:iam::{parsed['account']}:policy/{policy}")

    return {"status": "UNKNOWN_IAM_RESOURCE"}

def get_elbv2_metadata(parsed):
    client = boto3.client("elbv2", region_name=parsed["region"])
    return client.describe_load_balancers(LoadBalancerArns=[
        f"arn:{parsed['partition']}:{parsed['service']}:{parsed['region']}:{parsed['account']}:{parsed['resource']}"
    ])

def get_backup_metadata(parsed):
    client = boto3.client("backup", region_name=parsed["region"])
    return client.get_recovery_point(
        BackupVaultName="default",
        RecoveryPointArn=f"arn:{parsed['partition']}:backup:{parsed['region']}:{parsed['account']}:{parsed['resource']}"
    )


# ------------------------------------------------------------------------------
# SERVICE → METADATA FUNCTION MAP
# ------------------------------------------------------------------------------
SERVICE_HANDLERS = {
    "rds": get_rds_metadata,
    "ec2": get_ec2_metadata,
    "kms": get_kms_metadata,
    "sqs": get_sqs_metadata,
    "lambda": get_lambda_metadata,
    "iam": get_iam_metadata,
    "elasticloadbalancing": get_elbv2_metadata,
    "backup": get_backup_metadata,
}

# ------------------------------------------------------------------------------
# MAIN ARN VALIDATION
# ------------------------------------------------------------------------------
def validate_arn(arn):
    logger.info(f"Checking ARN: {arn}")

    parsed = parse_arn(arn)
    if not parsed:
        return {"arn": arn, "status": "INVALID_ARN_FORMAT"}

    service = parsed["service"]

    if service not in SERVICE_HANDLERS:
        return {"arn": arn, "status": "UNSUPPORTED_SERVICE"}

    try:
        metadata = SERVICE_HANDLERS[service](parsed)
        return {
            "arn": arn,
            "status": "SUCCESS",
            "metadata": metadata
        }

    except ClientError as ce:
        return {"arn": arn, "status": "FAILED", "error": str(ce)}
    except Exception as e:
        return {"arn": arn, "status": "FAILED", "error": str(e)}

# ------------------------------------------------------------------------------
# PROCESS YAML COMPONENTS
# ------------------------------------------------------------------------------
def process_yaml(yaml_file):
    with open(yaml_file, "r") as f:
        deployment = yaml.safe_load(f)

    components = deployment["data"]["deployment"]["components"]
    final_output = []

    for comp in components:
        comp_name = comp["componentName"]
        comp_type = comp["componentType"]
        arns = comp.get("arns", [])

        logger.info(f"Processing component: {comp_name}")

        comp_result = {
            "componentName": comp_name,
            "componentType": comp_type,
            "arnResults": []
        }

        for arn in arns:
            comp_result["arnResults"].append(validate_arn(arn))

        final_output.append(comp_result)

    return final_output

# ------------------------------------------------------------------------------
# CLI ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AWS ARN metadata/health check script")
    parser.add_argument("yaml_file", help="Deployment YAML with components and ARNs")
    args = parser.parse_args()

    results = process_yaml(args.yaml_file)
    print(json.dumps(results, indent=2))
