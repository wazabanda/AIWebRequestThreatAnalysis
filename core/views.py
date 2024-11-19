from django.shortcuts import redirect, render
from django.views.generic import TemplateView,View
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import *
# Create your views here.


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
        context["bad_percentage"] = round((len(bad_requests) / len(requests)) * 100,3)
        context['sus_ips'] = sus_ips
        return render(request,self.template_name,context)


class SuspicousIpView(LoginRequiredMixin,View):
    template_name = "core/dash2.html"

    def get(self,request,id):
        suspicous_ip = SuspicousIP.objects.get(id=id)

        context = {}
        context['sus'] = suspicous_ip

        return render(request,self.template_name,context)
