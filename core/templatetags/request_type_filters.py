# In your_app/templatetags/request_type_filters.py
from django import template

register = template.Library()

@register.simple_tag
def request_type_color(request_type):
    request_type = str(request_type).upper()
    
    REQUEST_TYPE_COLORS = {
        'GOOD': {
            'text': 'text-green-600',
            'bg': 'bg-green-100',
            'description': 'Safe Request'
        },
        'BAD': {
            'text': 'text-red-600',
            'bg': 'bg-red-100',
            'description': 'Potential Threat'
        },
        'BAD_ENTRY': {
            'text': 'text-yellow-600',
            'bg': 'bg-yellow-100',
            'description': 'Suspicious Entry'
        },
        'CHECK': {
            'text': 'text-blue-600',
            'bg': 'bg-blue-100',
            'description': 'Needs Review'
        },
        'WARNING': {
            'text': 'text-orange-600',
            'bg': 'bg-orange-100',
            'description': 'Potential Issue'
        }
    }
    
    type_info = REQUEST_TYPE_COLORS.get(request_type, {
        'text': 'text-gray-500',
        'bg': 'bg-gray-100',
        'description': 'Unknown'
    })
    
    return type_info

@register.simple_tag
def request_type_description(request_type):
    result = request_type_color(request_type)
    return result.get('description', 'Unknown')