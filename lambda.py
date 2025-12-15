import asyncio
from core.aws_async_session import AsyncAWSSession
from services.lambda_checker_async import AsyncLambdaChecker
from services.nlb_checker_async import AsyncNLBChecker
from services.kms_checker_async import AsyncKMSChecker

async def run_checks():
    session = AsyncAWSSession(region="ap-south-1")

    async with session.client("lambda") as lambda_client, \
               session.client("cloudwatch") as cw_client, \
               session.client("elbv2") as elbv2_client, \
               session.client("kms") as kms_client:

        lambda_checker = AsyncLambdaChecker(lambda_client, cw_client)
        nlb_checker = AsyncNLBChecker(elbv2_client)
        kms_checker = AsyncKMSChecker(kms_client)

        results = await asyncio.gather(
            lambda_checker.check_availability(),
            lambda_checker.check_performance(),
            lambda_checker.check_configuration(),
            nlb_checker.check_availability(),
            nlb_checker.check_configuration(),
            kms_checker.check_availability(),
            kms_checker.check_configuration(),
        )

        
        return [item for sublist in results for item in sublist]

if _name_ == "_main_":
    output = asyncio.run(run_checks())
    for r in output:
        print(r)