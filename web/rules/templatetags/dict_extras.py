# rules/templatetags/dict_extras.py
from django import template
register = template.Library()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key) if isinstance(dictionary, dict) else None
