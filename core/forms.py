# core/forms.py
from django import forms
from .models import Producto
from decimal import Decimal


class ProductoForm(forms.ModelForm):
    class Meta:
        model = Producto
        fields = [
            'codigo_barras', 'nombre', 'categoria', 'precio', 'stock',
            'unidad_medida', 'tamano_paquete', 'producto_hijo',
            'fecha_vencimiento', 'imagen', 'activo'
        ]
        widgets = { ... }  # tu código actual

        labels = { ... }  # tu código actual

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        if not self.instance.pk:
            self.fields['codigo_barras'].required = False
            self.fields['codigo_barras'].help_text = "Se generará automáticamente (ej: MAN-00123)"
            self.fields['codigo_barras'].widget.attrs['placeholder'] = "Dejar vacío para autogenerar"
        else:
            self.fields['codigo_barras'].widget.attrs['readonly'] = True 

        # Forzar precio entero en edición
        if self.instance.pk and self.instance.precio:
            self.initial['precio'] = int(self.instance.precio)
        
        self.fields['precio'].widget.attrs.update({
            'step': '1',
            'min': '0',
            'class': 'form-control text-end',
            'placeholder': '15000'
        })

    # === MÉTODOS CLEAN ===
    def clean_precio(self):
        precio = self.cleaned_data.get('precio')
        if precio is not None:
            try:
                precio_entero = int(float(precio))
                if precio_entero < 0:
                    raise forms.ValidationError("El precio no puede ser negativo.")
                return precio_entero
            except (ValueError, TypeError):
                raise forms.ValidationError("Ingresa un precio válido (solo números enteros).")
        return precio

    def clean_stock(self):
        stock = self.cleaned_data.get('stock')
        if stock is not None:
            try:
                from decimal import Decimal, InvalidOperation
                stock_decimal = Decimal(str(stock)).quantize(Decimal('0.001'))
                if stock_decimal < 0:
                    raise forms.ValidationError("El stock no puede ser negativo.")
                return stock_decimal
            except (InvalidOperation, ValueError, TypeError):
                raise forms.ValidationError("Ingresa un stock válido (ej: 10 o 10.500).")
        return stock

    def clean_tamano_paquete(self):
        tamano = self.cleaned_data.get('tamano_paquete')
        if tamano is not None:
            try:
                from decimal import Decimal, InvalidOperation
                tamano_decimal = Decimal(str(tamano)).quantize(Decimal('0.001'))
                if tamano_decimal <= 0:
                    raise forms.ValidationError("El tamaño del paquete debe ser mayor a 0.")
                return tamano_decimal
            except (InvalidOperation, ValueError, TypeError):
                raise forms.ValidationError("Ingresa un valor válido (ej: 12 o 12.000).")
        return tamano
    
    


class EscaneoEntradaForm(forms.Form):
    codigo_barras = forms.CharField(max_length=50, widget=forms.HiddenInput())
    cantidad = forms.DecimalField(
        label="Cantidad",
        min_value=Decimal('0.001'),
        decimal_places=3,
        initial=Decimal('1.000'),
        widget=forms.NumberInput(attrs={
            'class': 'form-control form-control-lg text-center',
            'step': 'any',
            'autofocus': True,
            'placeholder': 'Ej: 10, 12.5, 1',
            'style': 'font-size: 2rem; height: 80px;'
        })
    )


class ProductoRapidoForm(forms.ModelForm):
    class Meta:
        model = Producto
        fields = ['nombre', 'categoria', 'precio', 'unidad_medida', 'fecha_vencimiento']  # ← precio, no precio_por_unidad
        widgets = {
            'nombre': forms.TextInput(attrs={'class': 'form-control form-control-lg'}),
            'categoria': forms.TextInput(attrs={'class': 'form-control form-control-lg'}),
            'precio': forms.NumberInput(attrs={'class': 'form-control form-control-lg', 'step': '1', 'placeholder': 'Precio en pesos'}),
            'unidad_medida': forms.Select(attrs={'class': 'form-select form-select-lg'}),
            'fecha_vencimiento': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        }
        labels = {
            'precio': 'Precio (CLP)',
        }


class ConfigurarPaqueteForm(forms.ModelForm):
    class Meta:
        model = Producto
        fields = ['tamano_paquete', 'producto_hijo']
        widgets = {
            'tamano_paquete': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.001'}),
            'producto_hijo': forms.Select(attrs={'class': 'form-select'}),
        }