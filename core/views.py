from django.shortcuts import redirect, render
from django.views.generic import TemplateView,View
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import *
from django.http import JsonResponse
from django.utils.dateparse import parse_datetime
# Create your views here.


def get_request_logs(request,id):
    suspicous_ip = SuspicousIP.objects.get(id=id)
    start_date = parse_datetime(request.GET.get('start_date'))
    end_date = parse_datetime(request.GET.get('end_date'))

    if not start_date or not end_date:
        return JsonResponse({"error": "Invalid date range"}, status=400)

    logs = RequestLog.objects.filter(timestamp__range=(start_date, end_date),source_ip=suspicous_ip.source_ip).order_by('timestamp')
    data = [
        {
            "id": log.id,
            "source_ip": log.source_ip,
            "path": log.path,
            "timestamp": log.timestamp.isoformat(),
            "method": log.method,
            "request_type": log.request_type,
            "response_status_code": log.response_status_code,
        }
        for log in logs
    ]
    return JsonResponse({"logs": data})


class BaseView(LoginRequiredMixin,TemplateView):
    template_name = "core/base.html"


class DashView(LoginRequiredMixin,View):
    template_name = "core/home.html"
    
    def get(self,request):
        redirects = RequestRedirect.objects.all()
        context = {}
        context['redirects'] = redirects
        return render(request,self.template_name,context)


class RouteDashboard(LoginRequiredMixin,View):
    template_name = "core/dash.html"


    def get(self,request,id):
        route = RequestRedirect.objects.get(id=id)
        requests = RequestLog.objects.filter(redirect=route)
        bad_requests = requests.filter(request_type="BAD")
        sus_ips = SuspicousIP.objects.filter(redirect=route)
        context = {}

        context["req"] = route
        context['total'] = len(requests)
        context["total_bad"] = len(bad_requests)
        context["bad_percentage"] = round((len(bad_requests) / len(requests)) * 100,3) if len(requests) > 0 else 0

        context['sus_ips'] = sus_ips
        return render(request,self.template_name,context)


class SuspicousIpView(LoginRequiredMixin,View):
    template_name = "core/dash2.html"

    def get(self,request,id):
        suspicous_ip = SuspicousIP.objects.get(id=id)
        logs = RequestLog.objects.filter(source_ip=suspicous_ip.source_ip)
        sus_logs = RequestLog.objects.filter(sus_ip=suspicous_ip)
        print(sus_logs) 
        context = {}
        context['sus'] = suspicous_ip
        context['logs'] = logs
        context['sus_logs'] = sus_logs
        context['total_logs'] = len(logs)
        context['percentage'] = round(len(sus_logs) / len(logs),2) * 100 if len(logs) > 0 else 0
        return render(request,self.template_name,context)
