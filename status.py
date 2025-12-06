import json
import yaml
import subprocess
import boto3
import sys

# ---------- UTILITY TO RUN INVENTORY COMMAND ----------
def run_inventory(yaml_file):
    """Runs the EAC inventory command and returns JSON."""
    cmd = ["eac", "deployment", "inventory", "-f", yaml_file, "--json"]
    output = subprocess.check_output(cmd)
    return json.loads(output)

# ---------- HEALTH CHECK FUNCTIONS FOR EACH COMPONENT ----------

def check_rds_aurora(arn):
    rds = boto3.client("rds")
    try:
        cluster_id = arn.split(":")[-1]
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_kms(arn):
    kms = boto3.client("kms")
    key_id = arn.split("/")[-1]
    try:
        resp = kms.describe_key(KeyId=key_id)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_management_host(arn):
    ec2 = boto3.client("ec2")
    instance_id = arn.split("/")[-1]
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_sqs(arn):
    sqs = boto3.client("sqs")
    try:
        attributes = sqs.get_queue_attributes(
            QueueUrl=f"https://sqs.amazonaws.com/{arn.split(':')[4]}/{arn.split(':')[-1]}",
            AttributeNames=['All']
        )
        return {"arn": arn, "status": "HEALTHY", "details": attributes}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_iam_role(arn):
    iam = boto3.client("iam")
    role_name = arn.split("/")[-1]
    try:
        resp = iam.get_role(RoleName=role_name)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_route53(arn):
    r53 = boto3.client("route53")
    try:
        # hosted zone ID is not inside ARN, so list is used
        resp = r53.list_resource_record_sets(HostedZoneId="ZONESHOULDPROVIDE")
        return {"arn": arn, "status": "UNKNOWN", "details": "Route53 ARN does not map directly"}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_nlb(arn):
    elb = boto3.client("elbv2")
    lb_arn = arn
    try:
        resp = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_alb(arn):
    return check_nlb(arn)

def check_ecs_cluster(arn):
    ecs = boto3.client("ecs")
    try:
        resp = ecs.describe_clusters(clusters=[arn])
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

def check_lambda(arn):
    lam = boto3.client("lambda")
    func = arn.split(":")[-1]
    try:
        resp = lam.get_function(FunctionName=func)
        return {"arn": arn, "status": "HEALTHY", "details": resp}
    except Exception as e:
        return {"arn": arn, "status": "UNHEALTHY", "error": str(e)}

# ---------- COMPONENT DISPATCHER ----------
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

# ---------- MAIN PROCESS ----------
def process_components(inventory_json):
    results = []
    components = inventory_json["data"]["deployment"]["components"]
    for comp in components:
        ctype = comp["componentType"]
        cname = comp["componentName"]

        checker = CHECK_MAP.get(ctype)
        if not checker:
            results.append({"component": cname, "type": ctype, "error": "No checker implemented"})
            continue

        for module in comp.get("tfModules", []):
            for arn in module.get("arns", []):
                result = checker(arn)
                result["componentType"] = ctype
                result["componentName"] = cname
                results.append(result)

    return results

# ---------- PROGRAM ENTRY ----------
if __name__ == "__main__":
    yaml_file = sys.argv[1]

    inventory_json = run_inventory(yaml_file)
    checks = process_components(inventory_json)

    print(json.dumps(checks, indent=4, default=str))
