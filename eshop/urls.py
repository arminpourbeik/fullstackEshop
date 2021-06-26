from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/root/", include("apps.api.urls.api_root")),
    path("api/", include("apps.api.urls.auth_urls")),
]
