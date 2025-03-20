from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', main_view, name='main'),
    path("google/login/", google_login, name="google_login"),
    path("login/oauth2/google", google_callback, name="google_callback"),
]