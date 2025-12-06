import json
import yaml
import subprocess
import boto3
import sys
import logging
from datetime import datetime

# ------------------------------------------------------
# LOGGING SETUP
# ------------------------------------------------------
LOG_FILE = "check_arns.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger()

logger.info("==== Script Started ====")

# ------------------------------------------------------
# Run Inventory Command
# ------------------------------------------------------
def run_inventory(yaml_file):
    logger.info(f"Running EAC inventory for file: {yaml_file}")
    try:
        cmd = ["eac", "deployment", "inventory", "-f", yaml_file, "--json"]
        output = subprocess.check_output(cmd)
        logger.info("EAC inventory command executed successfully.")
        return json.loads(output)
    except Exception as e:
        logger.error(f"Error running EAC inventory command: {str(e)}")
        raise

# ------------------------------------------------------
# Component Health Check Functions
# ------------------------------------------------------
def check_rds_aurora(arn):
    rds = boto3.client("rds")
    logger.info(f"Checking RDS Aurora ARN: {arn}")
    try:
        cluster_id = arn.split(":")[-1]
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"RDS Aurora check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_kms(arn):
    kms = boto3.client("kms")
    logger.info(f"Checking KMS ARN: {arn}")
    key_id = arn.split("/")[-1]
    try:
        resp = kms.describe_key(KeyId=key_id)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"KMS check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_management_host(arn):
    ec2 = boto3.client("ec2")
    logger.info(f"Checking Management Host ARN: {arn}")
    instance_id = arn.split("/")[-1]
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"ManagementHost check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_sqs(arn):
    sqs = boto3.client("sqs")
    logger.info(f"Checking SQS ARN: {arn}")
    try:
        account = arn.split(":")[4]
        queue_name = arn.split(":")[-1]
        queue_url = f"https://sqs.amazonaws.com/{account}/{queue_name}"

        attributes = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['All']
        )
        return {"arn": arn, "status": "HEALTHY", "details": attributes}
    except Exception as e:
        logger.error(f"SQS check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_iam_role(arn):
    iam = boto3.client("iam")
    logger.info(f"Checking IAM Role ARN: {arn}")
    role_name = arn.split("/")[-1]
    try:
        resp = iam.get_role(RoleName=role_name)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"IAM role check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_route53(arn):
    logger.info(f"Checking Route53 ARN (limited support): {arn}")
    return {
        "arn": arn,
        "status": "UNKNOWN",
        "details": "Route53 health check requires HostedZoneID which is not in ARN."
    }

def check_nlb(arn):
    elb = boto3.client("elbv2")
    logger.info(f"Checking NLB ARN: {arn}")
    try:
        resp = elb.describe_load_balancers(LoadBalancerArns=[arn])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"NLB check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_alb(arn):
    logger.info(f"Checking ALB ARN: {arn}")
    return check_nlb(arn)

def check_ecs_cluster(arn):
    ecs = boto3.client("ecs")
    logger.info(f"Checking ECS Cluster ARN: {arn}")
    try:
        resp = ecs.describe_clusters(clusters=[arn])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"ECS cluster check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_lambda(arn):
    lam = boto3.client("lambda")
    logger.info(f"Checking Lambda ARN: {arn}")
    func = arn.split(":")[-1]
    try:
        resp = lam.get_function(FunctionName=func)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        logger.error(f"Lambda check failed: {arn} -> {str(e)}")
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

# ------------------------------------------------------
# Component Dispatcher
# ------------------------------------------------------
CHECK_MAP = {
    "RDSAuroraPostgres": check_rds_aurora,
    "KMS": check_kms,
    "ManagementHost": check_management_host,
    "SQS": check_sqs,
    "GlobalRoles": check_iam_role,
    "Roles": check_iam_role,
    "Route53Record": check_route53,
    "NetworkLoadBalancer": check_nlb,
    "ApplicationLoadBalancer": check_alb,
    "ECSCluster": check_ecs_cluster,
    "Lambda": check_lambda
}

# ------------------------------------------------------
# Process Components
# ------------------------------------------------------
def process_components(inventory_json):
    logger.info("Processing components from inventory JSON.")

    results = []
    components = inventory_json["data"]["deployment"]["components"]

    for comp in components:
        ctype = comp["componentType"]
        cname = comp["componentName"]

        logger.info(f"Processing component: {cname} ({ctype})")

        checker = CHECK_MAP.get(ctype)
        if not checker:
            logger.warning(f"No checker implemented for {ctype}")
            results.append({"component": cname, "type": ctype, "error": "No checker implemented"})
            continue

        for module in comp.get("tfModules", []):
            for arn in module.get("arns", []):
                logger.info(f"Checking ARN: {arn}")
                result = checker(arn)
                result["componentType"] = ctype
                result["componentName"] = cname
                results.append(result)

    return results

# ------------------------------------------------------
# Main
# ------------------------------------------------------
if __name__ == "__main__":
    yaml_file = sys.argv[1]

    logger.info(f"Starting ARN health checks for YAML: {yaml_file}")

    inventory_json = run_inventory(yaml_file)
    checks = process_components(inventory_json)

    logger.info("All ARN checks completed.")
    logger.info("==== Script Finished ====")

    print(json.dumps(checks, indent=4, default=str))
