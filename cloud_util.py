import datetime

async def get_metric_async(
    cw_client,
    namespace,
    metric_name,
    dimension_name,
    dimension_value
):
    response = await cw_client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
        StartTime=datetime.datetime.utcnow() - datetime.timedelta(minutes=5),
        EndTime=datetime.datetime.utcnow(),
        Period=300,
        Statistics=["Sum"]
    )

    datapoints = response.get("Datapoints", [])
    return datapoints[0]["Sum"] if datapoints else 0