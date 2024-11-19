
from core.models import *
from asgiref.sync import sync_to_async
from datetime import timedelta
from fastapi import  Request


async def get_suspicious_ip_async(source_ip,redirect):
    one_hour_ago = timezone.now() - timedelta(seconds=3600)

    return await sync_to_async(
        lambda: SuspicousIP.objects.filter(source_ip=source_ip, time_identified__gte=one_hour_ago,redirect=redirect).exists()
    )()


async def fetch_suspicious_ip_async(source_ip,redirect):
    one_hour_ago = timezone.now() - timedelta(seconds=3600)

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
    one_hour_ago = timezone.now() - timedelta(seconds=3600)

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


async def create_request_log(source_ip,redirect,request:Request,req_class,sus_ip):
    query_parsm = request.query_params
    path = request.url
    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    headers = dict(request.headers)
    method = request.method

    await sync_to_async(
            lambda: RequestLog.objects.create(source_ip=source_ip,path=path,body=body,headers=headers,method=method,
                    request_type="GOOD" if not req_class else "BAD",redirect=redirect,sus_ip=sus_ip)
    )()


