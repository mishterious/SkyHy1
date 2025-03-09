from django import template
register = template.Library()

@register.filter
def substring_back(String, i):
    return String[ : int(i)]