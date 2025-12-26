from django import template

register = template.Library()

@register.filter
def mul(value, arg):
    """Multiplica dos números"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0

@register.filter
def sub(value, arg):
    """Resta dos números"""
    try:
        return float(value) - float(arg)
    except (ValueError, TypeError):
        return value

# === NUEVO FILTRO PARA SUMAR ATRIBUTO DE UN QUERSET ===
@register.filter
def sum_attribute(queryset, attribute):
    """Suma el valor de un atributo en un queryset"""
    try:
        return sum(getattr(obj, attribute) or 0 for obj in queryset)
    except:
        return 0