# detection/urls.py
from django.urls import path, include
from . import views # Import your views normally
# Import the class-based views specifically for URL patterns
from .views import (
    alert_list, dashboard, # Keep existing function views if needed
    SQLiPatternListView, SQLiPatternCreateView, SQLiPatternUpdateView, SQLiPatternDeleteView,
    DDoSConfigUpdateView,
    PortSpecificDDoSConfigListView, PortSpecificDDoSConfigCreateView,
    PortSpecificDDoSConfigUpdateView, PortSpecificDDoSConfigDeleteView,
    BlockedIPListView, block_ip_manually_view, unblock_ip_view,
)

urlpatterns = [
# Dashboard at the root of the app's prefix (e.g., /ids/)
    path('', views.dashboard, name='home'), # Renamed from 'dashboard' to 'home' to match project root redirect if used

    # Existing/Dashboard/Alert Views
    path('alerts/', views.alert_list, name='alert_list'),
    path('packets/', views.realtime_packets, name='realtime_packets'),
    path('map/', views.geolocation_map, name='geolocation_map'),
    path('export/', views.export_data_view, name='export_data'),

    # --- Central Rules Management Page ---
    path('rules/', views.manage_rules_view, name='manage_rules'),

    # --- Specific Rule Type URLs ---
    # SQLi Pattern URLs
    path('rules/sqli/', SQLiPatternListView.as_view(), name='sqli_pattern_list'),
    path('rules/sqli/new/', SQLiPatternCreateView.as_view(), name='sqli_pattern_create'),
    path('rules/sqli/<int:pk>/update/', SQLiPatternUpdateView.as_view(), name='sqli_pattern_update'),
    path('rules/sqli/<int:pk>/delete/', SQLiPatternDeleteView.as_view(), name='sqli_pattern_delete'),
    # Default DDoS Config URL
    path('rules/ddos/default/', DDoSConfigUpdateView.as_view(), name='ddos_config_update'),
    # Port-Specific DDoS Rule URLs
    path('rules/ddos/ports/', PortSpecificDDoSConfigListView.as_view(), name='port_specific_ddos_list'),
    path('rules/ddos/ports/new/', PortSpecificDDoSConfigCreateView.as_view(), name='port_specific_ddos_create'),
    path('rules/ddos/ports/<int:pk>/update/', PortSpecificDDoSConfigUpdateView.as_view(), name='port_specific_ddos_update'),
    path('rules/ddos/ports/<int:pk>/delete/', PortSpecificDDoSConfigDeleteView.as_view(), name='port_specific_ddos_delete'),
    path('blocks/', BlockedIPListView.as_view(), name='blocked_ip_list'),
    path('blocks/add/', views.block_ip_manually_view, name='block_ip_manually'), # Handles POST from list page form
    path('blocks/<int:pk>/unblock/', views.unblock_ip_view, name='unblock_ip'), # Handles POST from list page buttons

]