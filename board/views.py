from pathlib import Path

import os
import requests

# id 검증에 필요한 google 패키지
from google.oauth2 import id_token
from google.auth.transport.requests import Request

from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from allauth.socialaccount.models import SocialAccount

from .models import *
from .forms import SignupForm
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Google OAuth 설정
GOOGLE_USERINFO_SCOPE = os.getenv("GOOGLE_USERINFO_SCOPE")
GOOGLE_LOGIN_PAGE = os.getenv("GOOGLE_LOGIN_PAGE")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN")

# 메인 페이지
def main_view(request):
    return render(request, 'main.html')

def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)

            # 비밀번호 해시해서 저장
            user.set_password(form.cleaned_data['password'])
            user.save()
            return redirect('/')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

# 일반 회원가입 사용자 로그인
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('/')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')

# 로그인 페이지 연결
def google_login(request):
   # 로그인에 사용할 정보의 범위 설정(로그인에는 email만)
   scope = GOOGLE_USERINFO_SCOPE

   # Google 로그인 페이지를 띄워 주는 역할
   return redirect(f"{GOOGLE_LOGIN_PAGE}?client_id={GOOGLE_CLIENT_ID}&response_type=code&redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}&access_type=offline&prompt=consent")

# 인가 코드를 받아 로그인 처리
def google_callback(request):
    # 프론트에서 인가 코드 받아옴
    code = request.GET.get("code")
    # 발급받은 Client ID, SECRET, 받은 인가 코드로 리소스 서버에 token 요청
    token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}")

    # 토큰 응답은 JSON으로 옴->json()으로 파싱
    token_data = token_request.json()
    google_access_token = token_data.get('access_token')
    google_refresh_token = token_data.get('refresh_token')
    google_id_token = token_data.get('id_token')

    # print("refresh token: ", google_refresh_token)

    # ID 토큰 유효성 검증
    # input: id token, client_id
    # output: 디코딩돼서 검증된 id token
    verified_token = id_token.verify_oauth2_token(
        google_id_token,
        Request(), # ??
        GOOGLE_CLIENT_ID,
    )

    email = verified_token.get('email')
    name = verified_token.get('name') # 없을 경우 none

    user = User.objects.filter(email=email).first()

    # 기존에 일반 회원가입했던 유저인 경우 → 소셜 계정 추가
    if user:
        try:
            social_user = SocialAccount.objects.get(user=user, provider="google")
            print("유저 확인: ", social_user)
            # 이미 Google로 가입한 유저면 바로 로그인 성공 처리
            response = JsonResponse({"status": 200, "message": "Login successful"})

            response = HttpResponseRedirect("/")
            
            response.set_cookie(
                key="access_token",
                value=google_access_token,
                httponly=True,
                secure=True,
                samesite="Lax"
            )

            response.set_cookie(
                key="refresh_token",
                value=google_refresh_token,
                httponly=True,
                secure=True,
                samesite="Lax"
            )
            return response
        
        except SocialAccount.DoesNotExist:
            # 기존에 일반 회원가입 유저인 경우 소셜 계정을 추가함
            SocialAccount.objects.create(user=user, provider="google", uid=email)
            return JsonResponse({"status": 200, "message": "Social account added"}, status=200)

    # 기존에 회원가입하지 않은 유저 → 가입 여부 묻기
    else:
        if not name:
            # 이름 정보가 없는 경우 프로필 범위를 추가하여 google에 토큰 다시 요청
            return redirect(
                f"{GOOGLE_LOGIN_PAGE}?client_id={GOOGLE_CLIENT_ID}&response_type=code&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20email%20profile&access_type=offline&prompt=consent"
            )

        # 이름 정보가 있으면 profile 받아온 것-> 회원가입 진행
        user = User.objects.create(email=email, username=name)
        user.set_unusable_password()
        user.save()

        # 소셜 계정 추가
        SocialAccount.objects.create(user=user, provider="google", uid=email)

        response = JsonResponse({"status": 200, "message": "Signup successful"})

        response.set_cookie(
            key="access_token",
            value=google_access_token,
            httponly=True,
            secure=True,
            samesite="Strict"
        )

        response.set_cookie(
            key="refresh_token",
            value=google_refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict"
        )
        return response

@api_view(['GET'])
def board_view(request):
    # 쿠키에서 access token 받아옴
    access_token = request.COOKIES.get("access_token")
    
    # access token 존재시 접근 허용
    if access_token:
        posts = Post.objects.all()
        return render(request, 'board.html', {'posts': posts})
    else:
        return JsonResponse({"message": "로그인이 필요합니다."}, status=401)