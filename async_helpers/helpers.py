
from os import supports_follow_symlinks
from core.models import *
from asgiref.sync import sync_to_async
from datetime import timedelta
from fastapi import  Request, Response

from fa_imp import sus


async def get_suspicious_ip_async(source_ip,redirect):
    one_hour_ago = timezone.now() - timedelta(seconds=60)

    return await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip, time_identified__gte=one_hour_ago,redirect=redirect).exists()
    )()


async def fetch_suspicious_ip_async(source_ip,redirect):
    one_hour_ago = timezone.now() - timedelta(seconds=60)

    return await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip, time_identified__gte=one_hour_ago,redirect=redirect).first()
    )()


async def create_suspicious_ip_async(source_ip, redirect):
    return await sync_to_async(
        lambda: SuspicousIP.objects.create(
            source_ip=source_ip,
            time_identified=timezone.now(),
            time_allowed=timezone.now(),
            redirect=redirect,
        )
    )()

async def is_time_expired_async(source_ip):
    one_hour_ago = timezone.now() - timedelta(seconds=30)

    return await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip, time_identified__lt=one_hour_ago).exists()
    )()


async def update_time_identified_async(source_ip):
    await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip).update(time_identified=timezone.now())
    )()



async def update_time_allowed_async(source_ip):
    await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip).update(time_allowed=timezone.now())
    )()


async def create_request_log(source_ip,redirect,request:Request,req_class,sus_ip,response:Response,is_new,analysis):
    import json
    query_parsm = request.query_params
    path = request.url.path + request.url.query
    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    # r_body = (await response.body()).decode("utf-8") 
    headers = json.dumps(dict(request.headers))
    method = request.method
    r_body = bytes(response.body).decode('utf-8')
    req_type = "GOOD" if not req_class else "BAD"
    if sus_ip and analysis and sus:
        req_type = "CHECK"
    if is_new:
        req_type = "BAD_ENTRY"

    await sync_to_async(
            lambda: RequestLog.objects.create(source_ip=source_ip,path=path,body=body,headers=headers,method=method,
                    request_type=req_type,redirect=redirect,sus_ip=sus_ip,response_body=r_body,response_status_code=str(response.status_code))
    )()


