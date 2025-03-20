from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', MainView.as_view(), name='main'),
    path("google/loginpage/", google_login_page, name="google_login"),
    path("login/oauth2/google", google_callback, name="google_callback"),
]