from django import template
import re

register = template.Library()

@register.simple_tag
def status_code_color(status_code):
    # Handle None or empty string
    if not status_code:
        return 'bg-gray-100 text-gray-800'
    
    # Remove any non-digit characters
    status_code_str = re.sub(r'\D', '', str(status_code))
    
    # Handle empty string after removing non-digits
    if not status_code_str:
        return 'bg-gray-100 text-gray-800'
    
    try:
        status_code = int(status_code_str)
    except ValueError:
        return 'bg-gray-100 text-gray-800'
    
    # Color mapping with range and specific code handling
    STATUS_CODE_COLORS = [
        ((200, 299), 'bg-green-100 text-green-800'),
        ((300, 399), 'bg-blue-100 text-blue-800'),
        ((400, 400), 'bg-orange-100 text-orange-800'),
        ((401, 401), 'bg-yellow-100 text-yellow-800'),
        ((403, 403), 'bg-red-100 text-red-800'),
        ((404, 404), 'bg-pink-100 text-pink-800'),
        ((400, 499), 'bg-yellow-100 text-yellow-800'),
        ((500, 599), 'bg-red-100 text-red-800'),
    ]
    
    for (start, end), color in STATUS_CODE_COLORS:
        if start <= status_code <= end:
            return color
    
    return 'bg-gray-100 text-gray-800'
