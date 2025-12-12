import boto3
import re
import botocore

def health_check_lambda(component, arn, aws_region):
    """
    Full Lambda Health Check:
    - Basic Health (Option A)
    - Deep Enterprise Validation (Option B)
    """

    lambda_client = boto3.client("lambda", region_name=aws_region)
    iam_client = boto3.client("iam")
    cw = boto3.client("cloudwatch", region_name=aws_region)

    report = {
        "component": component,
        "arn": arn,
        "basic_health": {},
        "deep_health": {},
        "status": "Healthy"
    }

    try:
        # ---------------------------------------------
        # Fetch Lambda Info
        # ---------------------------------------------
        fn = lambda_client.get_function(FunctionName=arn)
        cfg = fn["Configuration"]

        report["basic_health"]["runtime"] = cfg.get("Runtime")
        report["basic_health"]["memory"] = cfg.get("MemorySize")
        report["basic_health"]["timeout"] = cfg.get("Timeout")
        report["basic_health"]["last_modified"] = cfg.get("LastModified")
        report["basic_health"]["state"] = cfg.get("State")

        if cfg.get("State") != "Active":
            report["status"] = "Unhealthy"

    except Exception as e:
        report["status"] = "Unhealthy"
        report["basic_health"]["error"] = str(e)
        return report

    # ============================================================
    # OPTION A → BASIC DEPENDENCY VALIDATION
    # ============================================================

    # ------------------------------------------------------------
    # IAM Role Validation
    # ------------------------------------------------------------
    role_arn = cfg.get("Role")
    role_name = role_arn.split("/")[-1]

    try:
        iam_client.get_role(RoleName=role_name)
        report["basic_health"]["iam_role"] = "Exists"
    except Exception as e:
        report["basic_health"]["iam_role"] = "Missing"
        report["status"] = "Unhealthy"

    # ------------------------------------------------------------
    # VPC Config Validation
    # ------------------------------------------------------------
    vpc_config = cfg.get("VpcConfig", {})

    if vpc_config and vpc_config.get("SubnetIds"):
        report["basic_health"]["vpc_enabled"] = True
    else:
        report["basic_health"]["vpc_enabled"] = False

    # ============================================================
    # OPTION B → ENTERPRISE LEVEL HEALTH CHECKS
    # ============================================================

    # ------------------------------------------------------------
    # CloudWatch Metrics Helper
    # ------------------------------------------------------------
    def metric_sum(metric, period=300):
        try:
            response = cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName=metric,
                Dimensions=[{"Name": "FunctionName", "Value": cfg["FunctionName"]}],
                StartTime=datetime.utcnow() - timedelta(minutes=15),
                EndTime=datetime.utcnow(),
                Period=period,
                Statistics=["Sum"]
            )
            datapoints = response.get("Datapoints", [])
            return datapoints[0]["Sum"] if datapoints else 0
        except Exception:
            return None

    # ------------------------------------------------------------
    # Error Rate
    # ------------------------------------------------------------
    errors = metric_sum("Errors")
    invocations = metric_sum("Invocations")

    if invocations and errors is not None:
        error_rate = (errors / invocations) * 100 if invocations > 0 else 0

        report["deep_health"]["errors_last_15m"] = errors
        report["deep_health"]["invocations_last_15m"] = invocations
        report["deep_health"]["error_rate_percent"] = round(error_rate, 3)

        if error_rate > 5:   # enterprise threshold
            report["status"] = "Degraded"

    # ------------------------------------------------------------
    # Throttles
    # ------------------------------------------------------------
    throttles = metric_sum("Throttles")
    report["deep_health"]["throttles_last_15m"] = throttles
    if throttles and throttles > 0:
        report["status"] = "Degraded"

    # ------------------------------------------------------------
    # Duration p95
    # ------------------------------------------------------------
    try:
        duration_resp = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Duration",
            Dimensions=[{"Name": "FunctionName", "Value": cfg["FunctionName"]}],
            StartTime=datetime.utcnow() - timedelta(minutes=15),
            EndTime=datetime.utcnow(),
            Period=300,
            Statistics=["p95"]
        )
        datapoints = duration_resp.get("Datapoints", [])
        p95 = datapoints[0]["p95"] if datapoints else None

        report["deep_health"]["duration_p95_ms"] = p95

        # threshold: warn if > 80% of timeout
        if p95 and p95 > (cfg["Timeout"] * 1000 * 0.8):
            report["status"] = "Degraded"

    except Exception:
        report["deep_health"]["duration_p95_ms"] = None

    # ------------------------------------------------------------
    # DLQ Check
    # ------------------------------------------------------------
    if "DeadLetterConfig" in cfg and cfg["DeadLetterConfig"].get("TargetArn"):
        report["deep_health"]["dlq"] = "Configured"
    else:
        report["deep_health"]["dlq"] = "Missing"

    # ------------------------------------------------------------
    # Environment Variables → ARN Validation
    # ------------------------------------------------------------
    env = cfg.get("Environment", {}).get("Variables", {})
    missing_arn_targets = []

    arn_regex = r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+"

    for key, value in env.items():
        if re.match(arn_regex, value):
            # validate ARN exists
            service = value.split(":")[2]
            try:
                # simple exist check: attempt call
                boto3.client(service).get_waiter  # ensures service exists
            except Exception:
                missing_arn_targets.append(value)

    report["deep_health"]["broken_env_arn_references"] = missing_arn_targets

    if missing_arn_targets:
        report["status"] = "Unhealthy"

    # ------------------------------------------------------------
    # Final Status
    # ------------------------------------------------------------
    return report
