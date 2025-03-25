from django.urls import path
from .views import *

urlpatterns = [
    path('', main_view, name='main'),
    path("google/login/", google_login, name="google_login"),
    path("login/status/", login_status, name="login_status"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("signup/", signup_view, name="signup"),
    path('board/', board_view, name='board'),
    path("login/oauth2/google/", google_callback, name="google_callback"),
]