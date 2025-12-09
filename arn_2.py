#!/usr/bin/env python3
import json
import boto3
import logging
import argparse
from botocore.exceptions import ClientError, EndpointConnectionError


#########################################
# Logging Configuration
#########################################
logging.basicConfig(
    filename='infra_health.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger()


#########################################
# Safe AWS call wrapper
#########################################
def safe_call(fn, **kwargs):
    try:
        return fn(**kwargs), None
    except (ClientError, EndpointConnectionError) as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


#########################################
# Individual Component Health Checkers
#########################################
def check_rds(name):
    client = boto3.client('rds')
    data, err = safe_call(client.describe_db_clusters, DBClusterIdentifier=name)

    if err:
        return {"componentType": "RDSAuroraPostgres", "componentName": name, "status": "DOWN", "error": err}

    status = data["DBClusters"][0]["Status"]
    return {"componentType": "RDSAuroraPostgres", "componentName": name, "status": status}


def check_kms(name):
    client = boto3.client('kms')
    data, err = safe_call(client.describe_key, KeyId=name)

    if err:
        return {"componentType": "KMS", "componentName": name, "status": "DOWN", "error": err}

    enabled = data["KeyMetadata"]["Enabled"]
    return {"componentType": "KMS", "componentName": name, "status": "Enabled" if enabled else "Disabled"}


def check_sqs(name):
    client = boto3.client('sqs')
    try:
        q_url = client.get_queue_url(QueueName=name)["QueueUrl"]
        attrs = client.get_queue_attributes(QueueUrl=q_url, AttributeNames=['All'])
        return {"componentType": "SQS", "componentName": name, "status": "UP", "attributes": attrs["Attributes"]}
    except Exception as e:
        return {"componentType": "SQS", "componentName": name, "status": "DOWN", "error": str(e)}


def check_nlb(name):
    client = boto3.client('elbv2')
    data, err = safe_call(client.describe_load_balancers, Names=[name])

    if err:
        return {"componentType": "NetworkLoadBalancer", "componentName": name, "status": "DOWN", "error": err}

    state = data["LoadBalancers"][0]["State"]["Code"]
    return {"componentType": "NetworkLoadBalancer", "componentName": name, "status": state}


def check_alb(name):
    client = boto3.client('elbv2')
    data, err = safe_call(client.describe_load_balancers, Names=[name])

    if err:
        return {"componentType": "ApplicationLoadBalancer", "componentName": name, "status": "DOWN", "error": err}

    state = data["LoadBalancers"][0]["State"]["Code"]
    return {"componentType": "ApplicationLoadBalancer", "componentName": name, "status": state}


def check_ecs(name):
    client = boto3.client('ecs')
    data, err = safe_call(client.describe_clusters, clusters=[name])

    if err:
        return {"componentType": "ECSCluster", "componentName": name, "status": "DOWN", "error": err}

    status = data["clusters"][0]["status"]
    return {"componentType": "ECSCluster", "componentName": name, "status": status}


def check_lambda(name):
    client = boto3.client('lambda')
    data, err = safe_call(client.get_function, FunctionName=name)

    if err:
        return {"componentType": "Lambda", "componentName": name, "status": "DOWN", "error": err}

    return {"componentType": "Lambda", "componentName": name, "status": "UP"}


def check_route53(name):
    client = boto3.client('route53')
    try:
        client.list_resource_record_sets(HostedZoneId=name)
        return {"componentType": "Route53Record", "componentName": name, "status": "UP"}
    except Exception as e:
        return {"componentType": "Route53Record", "componentName": name, "status": "DOWN", "error": str(e)}


def check_roles(name):
    client = boto3.client('iam')
    try:
        client.get_role(RoleName=name)
        return {"componentType": "Roles", "componentName": name, "status": "UP"}
    except Exception as e:
        return {"componentType": "Roles", "componentName": name, "status": "DOWN", "error": str(e)}


def check_global_roles(name):
    return check_roles(name)


def check_mgmt_host(name):
    # Infra-only placeholder
    return {"componentType": "ManagementHost", "componentName": name, "status": "N/A"}


#########################################
# Component-type → function mapping
#########################################
CHECK_MAP = {
    "RDSAuroraPostgres": check_rds,
    "KMS": check_kms,
    "SQS": check_sqs,
    "NetworkLoadBalancer": check_nlb,
    "ApplicationLoadBalancer": check_alb,
    "ECSCluster": check_ecs,
    "Lambda": check_lambda,
    "Route53Record": check_route53,
    "Roles": check_roles,
    "GlobalRoles": check_global_roles,
    "ManagementHost": check_mgmt_host
}


#########################################
# Main Program
#########################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json_file", required=True,
                        help="JSON output from: eac deployment inventory deployment.yaml --json")
    args = parser.parse_args()

    with open(args.json_file) as f:
        items = json.load(f)

    results = []

    for comp in items:
        ctype = comp.get("Type")
        cname = comp.get("Name")

        logger.info(f"Checking {ctype}: {cname}")

        checker = CHECK_MAP.get(ctype)

        if not checker:
            result = {"componentType": ctype, "componentName": cname, "status": "UNKNOWN"}
            results.append(result)
            logger.warning(f"No checker for {ctype}")
            continue

        result = checker(cname)
        results.append(result)

        logger.info(f"Result: {result}")

    # Output to CLI
    print(json.dumps(results, indent=4))

    # Also store results in log file
    logger.info("Final Output:")
    logger.info(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
