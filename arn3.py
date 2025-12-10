import boto3
import csv
import datetime

# -----------------------------------------
# GLOBAL CONFIG
# -----------------------------------------
CPU_THRESHOLD_RDS = 80.0
LAMBDA_ERROR_THRESHOLD = 5
SQS_MAX_AGE_THRESHOLD = 300  # 5 minutes
ELB_5XX_THRESHOLD = 10

NOW = datetime.datetime.utcnow()
START = NOW - datetime.timedelta(minutes=10)
END = NOW

# AWS Clients
rds = boto3.client("rds")
cw = boto3.client("cloudwatch")
kms = boto3.client("kms")
ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sqs = boto3.client("sqs")
route53 = boto3.client("route53")
lambda_client = boto3.client("lambda")
ecs = boto3.client("ecs")
elbv2 = boto3.client("elbv2")

deployment_components = {
    "RDSAuroraPostgres": "rasaurora",
    "KMS": "rdskey",
    "ManagementHost": "dbmgnt",
    "SQS": "cbisnfsqs",
    "GlobalRoles": "gbrole",
    "Roles_ecs": "ecsrole",
    "Roles_lambda": "Lambdarole",
    "Route53Record": "dns",
    "NetworkLoadBalancer": "ecsnlb",
    "ApplicationLoadBalancer": "ecsalb",
    "ECSCluster": "ecs",
    "Lambda": "cbidbmgmt"
}

results = []


# -----------------------------------------------------
# RDS AURORA POSTGRES
# -----------------------------------------------------
def check_rds():
    name = deployment_components["RDSAuroraPostgres"]

    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=name)["DBClusters"]
        status = clusters[0]["Status"]

        health = "HEALTHY" if status == "available" else "UNHEALTHY"
        cpu_note = ""

        # CPU check for each instance in the cluster
        for inst in clusters[0]["DBClusterMembers"]:
            inst_id = inst["DBInstanceIdentifier"]

            metric = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": inst_id}],
                StartTime=START,
                EndTime=END,
                Period=300,
                Statistics=["Average"]
            )

            datapoints = metric.get("Datapoints", [])
            if datapoints:
                cpu = datapoints[-1]["Average"]
                cpu_note += f"{inst_id}: CPU={cpu:.1f}%; "
                if cpu > CPU_THRESHOLD_RDS:
                    health = "UNHEALTHY"
                    cpu_note += "(High CPU) "
            else:
                cpu_note += f"{inst_id}: No CPU metrics; "

        results.append({
            "Service": "RDSAuroraPostgres",
            "ResourceId": name,
            "Status": health,
            "Note": f"Cluster={status}; {cpu_note}"
        })

    except Exception as e:
        results.append({
            "Service": "RDSAuroraPostgres",
            "ResourceId": name,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# KMS KEY
# -----------------------------------------------------
def check_kms():
    key_id = deployment_components["KMS"]

    try:
        key = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        enabled = key["Enabled"]
        rotation = kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]

        status = "HEALTHY" if enabled else "UNHEALTHY"
        note = f"Enabled={enabled}, Rotation={rotation}"

        results.append({
            "Service": "KMS",
            "ResourceId": key_id,
            "Status": status,
            "Note": note
        })
    except Exception as e:
        results.append({
            "Service": "KMS",
            "ResourceId": key_id,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# EC2 (Management Host)
# -----------------------------------------------------
def check_management_host():
    expected_name = deployment_components["ManagementHost"]

    try:
        all_instances = ec2.describe_instances()
        found = False

        for res in all_instances["Reservations"]:
            for inst in res["Instances"]:
                name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), None)

                if name_tag == expected_name:
                    found = True
                    state = inst["State"]["Name"]
                    status = "HEALTHY" if state == "running" else "UNHEALTHY"

                    results.append({
                        "Service": "ManagementHost",
                        "ResourceId": inst["InstanceId"],
                        "Status": status,
                        "Note": f"State={state}"
                    })

        if not found:
            results.append({
                "Service": "ManagementHost",
                "ResourceId": expected_name,
                "Status": "NOT FOUND",
                "Note": "EC2 instance not present"
            })

    except Exception as e:
        results.append({
            "Service": "ManagementHost",
            "ResourceId": expected_name,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# SQS
# -----------------------------------------------------
def check_sqs():
    queue_name = deployment_components["SQS"]

    try:
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
        attrs = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateAgeOfOldestMessage"]
        )["Attributes"]

        count = int(attrs["ApproximateNumberOfMessages"])
        age = int(attrs["ApproximateAgeOfOldestMessage"])

        status = "HEALTHY"
        note = f"Messages={count}, OldestMessageAge={age}s"

        if age > SQS_MAX_AGE_THRESHOLD:
            status = "UNHEALTHY"
            note += " (Delayed messages)"

        results.append({
            "Service": "SQS",
            "ResourceId": queue_name,
            "Status": status,
            "Note": note
        })
    except Exception as e:
        results.append({
            "Service": "SQS",
            "ResourceId": queue_name,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# IAM ROLES
# -----------------------------------------------------
def check_iam_role(role_name, service_name):
    try:
        iam.get_role(RoleName=role_name)
        results.append({
            "Service": service_name,
            "ResourceId": role_name,
            "Status": "HEALTHY",
            "Note": "Role exists"
        })
    except Exception:
        results.append({
            "Service": service_name,
            "ResourceId": role_name,
            "Status": "NOT FOUND",
            "Note": "IAM Role missing"
        })


# -----------------------------------------------------
# ROUTE 53
# -----------------------------------------------------
def check_route53():
    record = deployment_components["Route53Record"]

    try:
        zones = route53.list_hosted_zones()["HostedZones"]
        found = False

        for zone in zones:
            recs = route53.list_resource_record_sets(HostedZoneId=zone["Id"])
            for r in recs["ResourceRecordSets"]:
                if record in r["Name"]:
                    found = True
                    results.append({
                        "Service": "Route53Record",
                        "ResourceId": record,
                        "Status": "HEALTHY",
                        "Note": f"RecordType={r['Type']}"
                    })

        if not found:
            results.append({
                "Service": "Route53Record",
                "ResourceId": record,
                "Status": "NOT FOUND",
                "Note": "DNS record not found"
            })

    except Exception as e:
        results.append({
            "Service": "Route53Record",
            "ResourceId": record,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# ELB (ALB + NLB)
# -----------------------------------------------------
def check_elb(lb_name):
    try:
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        for lb in lbs:
            if lb["LoadBalancerName"] == lb_name:
                arn = lb["LoadBalancerArn"]
                lb_type = lb["Type"]

                # Metric
                metric = cw.get_metric_statistics(
                    Namespace="AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB",
                    MetricName="HTTPCode_ELB_5XX_Count" if lb_type == "application" else "TCP_Client_Reset_Count",
                    Dimensions=[{"Name": "LoadBalancer", "Value": arn.split("loadbalancer/")[-1]}],
                    StartTime=START,
                    EndTime=END,
                    Period=300,
                    Statistics=["Sum"]
                )

                datapoints = metric.get("Datapoints", [])
                errors = int(datapoints[-1]["Sum"]) if datapoints else 0

                status = "HEALTHY" if errors <= ELB_5XX_THRESHOLD else "UNHEALTHY"

                results.append({
                    "Service": lb_type.upper(),
                    "ResourceId": lb_name,
                    "Status": status,
                    "Note": f"5XX errors={errors}"
                })
                return

        results.append({
            "Service": "ELB",
            "ResourceId": lb_name,
            "Status": "NOT FOUND",
            "Note": "Load balancer missing"
        })

    except Exception as e:
        results.append({
            "Service": "ELB",
            "ResourceId": lb_name,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# ECS CLUSTER
# -----------------------------------------------------
def check_ecs_cluster():
    cluster = deployment_components["ECSCluster"]

    try:
        resp = ecs.describe_clusters(clusters=[cluster])
        cl = resp["clusters"][0]

        status = cl["status"]
        running = cl["runningTasksCount"]

        results.append({
            "Service": "ECSCluster",
            "ResourceId": cluster,
            "Status": "HEALTHY" if status == "ACTIVE" else "UNHEALTHY",
            "Note": f"Status={status}, RunningTasks={running}"
        })
    except Exception as e:
        results.append({
            "Service": "ECSCluster",
            "ResourceId": cluster,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# LAMBDA
# -----------------------------------------------------
def check_lambda():
    name = deployment_components["Lambda"]

    try:
        config = lambda_client.get_function_configuration(FunctionName=name)
        state = config.get("State", "Unknown")

        metric = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Errors",
            Dimensions=[{"Name": "FunctionName", "Value": name}],
            StartTime=START,
            EndTime=END,
            Period=300,
            Statistics=["Sum"]
        )

        datapoints = metric.get("Datapoints", [])
        errors = int(datapoints[-1]["Sum"]) if datapoints else 0

        status = "HEALTHY" if (state == "Active" and errors < LAMBDA_ERROR_THRESHOLD) else "UNHEALTHY"

        results.append({
            "Service": "Lambda",
            "ResourceId": name,
            "Status": status,
            "Note": f"State={state}, Errors={errors}"
        })
    except Exception as e:
        results.append({
            "Service": "Lambda",
            "ResourceId": name,
            "Status": "ERROR",
            "Note": str(e)
        })


# -----------------------------------------------------
# SAVE CSV
# -----------------------------------------------------
def save_csv():
    headers = ["Service", "ResourceId", "Status", "Note"]
    with open("infra_health_check.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)


def main():
    check_rds()
    check_kms()
    check_management_host()
    check_sqs()
    check_iam_role("gbrole", "GlobalRoles")   
    check_iam_role("ecsrole", "Roles_ecs")
    check_iam_role("Lambdarole", "Roles_lambda")
    check_route53()
    check_elb("ecsnlb")
    check_elb("ecsalb")
    check_ecs_cluster()
    check_lambda()

    save_csv()
    print("✔ infra_health_check.csv generated.")


if __name__ == "__main__":
    main()
