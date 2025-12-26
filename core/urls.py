from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core import views  # Importa el módulo views de core
from django.urls import path
from . import views
from .views import CrearOrdenView
urlpatterns = [
    path('sistema/', admin.site.urls),
    path('', views.home, name='home'),
    path('catalogo/', views.catalogo, name='catalogo'),
    path('carrito/', views.carrito, name='carrito'),
    path('mis-compras/', views.mis_compras, name='mis_compras'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('panel/', views.admin_panel, name='admin_panel'),   
    path('add_to_carrito/<int:producto_id>/', views.add_to_carrito, name='add_to_carrito'),
    path('remove_from_carrito/<int:item_id>/', views.remove_from_carrito, name='remove_from_carrito'),
    path('api/productos/', views.ProductoListAPIView.as_view(), name='producto_list_api'),
    path('checkout/', views.checkout, name='checkout'),
    path('admin_home/', views.admin_home, name='admin_home'),
    path('admin/producto/crear/', views.producto_create, name='producto_create'),
    path('admin/producto/editar/<int:producto_id>/', views.producto_update, name='producto_update'),
    path('admin/producto/eliminar/<int:producto_id>/', views.producto_delete, name='producto_delete'),
    path('admin/productos/', views.producto_list, name='producto_list'),
    path('panel/orden/<int:pk>/', views.orden_detail, name='orden_detail'),
    path('crear-orden/', CrearOrdenView.as_view(), name='crear_orden'),
    #path('probar-orden/', ProbarOrdenView.as_view(), name='probar_orden'),
    path('test-endpoint/', views.test_endpoint_view, name='test_endpoint'),
    path('admin/orden/<int:orden_id>/actualizar/', views.update_orden_status, name='update_orden_status'),
    path('mis-compras/', views.mis_compras, name='mis_compras'),
    path('verificar-codigo/', views.verificar_codigo, name='verificar_codigo'),
    path('orden-exitosa/<int:orden_id>/', views.orden_exitosa, name='orden_exitosa'),
    path('escaneo/', views.escaneo_rapido, name='escaneo_rapido'),
    path('escaneo/editar/<int:pk>/', views.escaneo_rapido, name='editar_precio_rapido'),
    path('gestion-pedidos/', views.gestion_estados, name='gestion_pedidos'),  # redirecciona vieja URL a nueva view
    path('gestion-estados/', views.gestion_estados, name='gestion_estados'),
    path('panel/cambiar-estado/<int:pk>/', views.cambiar_estado_pedido, name='cambiar_estado_pedido'),
    
    path('pedidos-finalizados/', views.pedidos_finalizados, name='pedidos_finalizados'),
    path('pedidos-despacho/', views.pedidos_despacho, name='pedidos_despacho'),
    path('test-correo/', views.test_correo),
    path('carrito/actualizar/<int:item_id>/', views.actualizar_cantidad_carrito, name='actualizar_cantidad_carrito'),
    path('autocompletar-direccion/', views.autocompletar_direccion, name='autocompletar_direccion'),
    path('reenviar-codigo/', views.reenviar_codigo, name='reenviar_codigo'),
    path('recuperar-password/', views.recuperar_password, name='recuperar_password'),
    path('cambiar-password/<str:token>/', views.cambiar_password_view, name='cambiar_password'),
    path('cambiar-correo-registro/', views.cambiar_correo_registro, name='cambiar_correo_registro'),
    path('admin/producto/crear-con-codigo/', views.redirigir_crear_producto_con_codigo, name='crear_producto_con_codigo'),
    path('panel/banners/', views.gestion_banners, name='gestion_banners'),
    
]
