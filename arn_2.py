import subprocess
import json
import boto3
import logging

# --- Setup logging ---
logging.basicConfig(
    filename="component_status.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def run_inventory(yaml_file):
    """Run CLI to get deployment inventory JSON."""
    cmd = ["eac", "deployment", "inventory", "-f", yaml_file, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

# --- Component-specific functions ---
def check_rdsaurora(arn, region):
    client = boto3.client("rds", region_name=region)
    try:
        if ":cluster-snapshot:" in arn:
            snapshot_id = arn.split(":")[-1]
            resp = client.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)
            status = resp["DBClusterSnapshots"][0]["Status"]
        elif ":cluster:" in arn:
            cluster_id = arn.split(":")[-1]
            resp = client.describe_db_clusters(DBClusterIdentifier=cluster_id)
            status = resp["DBClusters"][0]["Status"]
        else:
            status = "Unknown"
        return "Success" if status.lower() in ["available", "active"] else "Failed"
    except Exception as e:
        logging.error(f"RDSAurora check failed for {arn}: {e}")
        return "Failed"

def check_kms(arn, region):
    client = boto3.client("kms", region_name=region)
    try:
        key_id = arn.split("/")[-1]
        resp = client.describe_key(KeyId=key_id)
        status = resp["KeyMetadata"]["KeyState"]
        return "Success" if status.lower() == "enabled" else "Failed"
    except Exception as e:
        logging.error(f"KMS check failed for {arn}: {e}")
        return "Failed"

def check_sqs(arn, region):
    client = boto3.client("sqs", region_name=region)
    try:
        queue_name = arn.split(":")[-1]
        queue_url = client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        # If we can fetch attributes, queue is healthy
        client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        return "Success"
    except Exception as e:
        logging.error(f"SQS check failed for {arn}: {e}")
        return "Failed"

def check_lambda(arn, region):
    client = boto3.client("lambda", region_name=region)
    try:
        func_name = arn.split(":")[-1]
        resp = client.get_function(FunctionName=func_name)
        state = resp["Configuration"].get("State", "Unknown")
        return "Success" if state.lower() == "active" else "Failed"
    except Exception as e:
        logging.error(f"Lambda check failed for {arn}: {e}")
        return "Failed"

def check_ecs(arn, region):
    client = boto3.client("ecs", region_name=region)
    try:
        cluster_name = arn.split("/")[-1]
        resp = client.describe_clusters(clusters=[cluster_name])
        status = resp["clusters"][0]["status"]
        return "Success" if status.lower() == "active" else "Failed"
    except Exception as e:
        logging.error(f"ECS check failed for {arn}: {e}")
        return "Failed"

# --- Dispatcher ---
def check_component(component_type, arn, region):
    if component_type == "RDSAuroraPostgres":
        return check_rdsaurora(arn, region)
    elif component_type == "KMS":
        return check_kms(arn, region)
    elif component_type == "SQS":
        return check_sqs(arn, region)
    elif component_type == "Lambda":
        return check_lambda(arn, region)
    elif component_type == "ECSCluster":
        return check_ecs(arn, region)
    else:
        logging.warning(f"No checker implemented for {component_type}")
        return "Failed"

def main(yaml_file):
    data = run_inventory(yaml_file)
    region = data["data"]["deployment"]["Environment"]["awsRegion"]
    components = data["data"]["deployment"]["components"]

    results = {}
    for comp in components:
        ctype = comp["componentType"]
        cname = comp["componentName"]
        results[cname] = {}
        for tfm in comp.get("tfModules", []):
            for arn in tfm.get("arns", []):
                status = check_component(ctype, arn, region)
                results[cname][arn] = status
                logging.info(f"{cname} ({ctype}) - {arn} -> {status}")

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main("deployment.yaml")
