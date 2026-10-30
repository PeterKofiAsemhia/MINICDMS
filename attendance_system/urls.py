from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # This line connects our core app's URLs to the main project
    path('', include('core.urls')), 
]