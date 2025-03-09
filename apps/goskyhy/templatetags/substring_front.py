from django import template
register = template.Library()

@register.filter
def substring_front(String, i):
    return String[int(i) : ]