from django.contrib import admin
from .models import RequestRedirect,SuspicousIP,RequestLog
# Register your models here.

@admin.register(RequestRedirect)
class RedirectAdmin(admin.ModelAdmin):
    list_display = ['name','source_route','good_redirect_route','bad_redirect_route']

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['source_ip','redirect','request_type','timestamp']

@admin.register(SuspicousIP)
class IPAmdin(admin.ModelAdmin):
    list_display  = ['source_ip','time_identified','time_allowed','redirect']
