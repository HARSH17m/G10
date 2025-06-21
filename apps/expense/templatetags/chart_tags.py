from django import template
register = template.Library()

@register.filter
def pluck(data, key):
    return [d[key] for d in data]