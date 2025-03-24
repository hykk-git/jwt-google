from pathlib import Path

import os
import jwt
import json
import requests

from google.oauth2 import id_token
from google.auth.transport.requests import Request

from django.shortcuts import redirect, render
from rest_framework import status
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
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

# 로그인 페이지 연결
def google_login(request):
   # 로그인에 사용할 정보의 범위 설정(이번에는 email만)
   scope = GOOGLE_USERINFO_SCOPE

   # Google 로그인 페이지를 띄워 주는 역할
   return redirect(f"{GOOGLE_LOGIN_PAGE}?client_id={GOOGLE_CLIENT_ID}&response_type=code&redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}&access_type=offline&prompt=consent")

# 인가 코드를 받아 로그인 처리
def google_callback(request):
    # 프론트에서 인가 코드 받아옴
    code = request.GET.get("code")  
    # 발급받은 Client ID, SECRET, 받은 인가 코드로 리소스 서버에 token 요청
    token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}")

    # 토큰 응답은 JSON으로 옴->json()으로 JSON 파싱
    token_data = token_request.json()
    google_access_token = token_data.get('access_token')
    google_refresh_token = token_data.get('refresh_token')
    google_id_token = token_data.get('id_token')

    # ID 토큰 유효성 검증
    # 원래 OAuth면 이 자리에 email 정보를 google한테 요청해 봐야 함
    # input: id token, client_id
    # output: 디코딩돼서 검증된 id token
    verified_token = id_token.verify_oauth2_token(
    google_id_token,
    Request(),
    GOOGLE_CLIENT_ID,
    )

    email = verified_token.get('email')

    try:
        # 기존 유저 이메일 확인
        try:
            user = User.objects.filter(email=email).first()
        except User.DoesNotExist:
            # 회원가입 여부를 묻는 알림을 클라이언트로 전달
            return JsonResponse({"status": 404, "message": "User not found", "email": email})

        # 소셜로그인 계정 유무 확인(Google)
        try:
            social_user = SocialAccount.objects.get(user=user)
            if social_user.provider != "google":
                return JsonResponse({"status": 400, "message": "User Account Not Exists"}, status=status.HTTP_400_BAD_REQUEST)
        except SocialAccount.DoesNotExist:
            SocialAccount.objects.create(user=user, provider="google", uid=email)
            return JsonResponse({"status": 200, "message": "Signup success"}, redirect('/'))
        # 로그인 성공 응답
        response = JsonResponse({"message": "login success",}, status=status.HTTP_200_OK,)

        # Refresh Token을 HttpOnly 쿠키로 설정
        response.set_cookie(
            key="refresh_token",
            value=google_refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict"
        )

        response.set_cookie(
            key="access_token",
            value=google_access_token,
            httponly=True,
            secure=True,
            samesite="Strict"
        )
        
        return response

    except Exception as e:
        return JsonResponse({"status": 400, "message": f"Serializer Errors: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

# 구글로 회원가입하기 위한 함수
def google_signup(request):
    token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20profile%20email")

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")

            if not email:
                return JsonResponse({"status": 400, "message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create(email=email)
            user.set_unusable_password()
            user.save()

            # 소셜 계정 추가
            SocialAccount.objects.create(user=user, provider="google", uid=email)
            return JsonResponse({"status": 200, "message": "Signup success"})
        except Exception as e:
            return JsonResponse({"status": 400, "message": f"Signup Failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    return JsonResponse({"status": 405, "message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# refresh token으로 새로운 access token을 발급받는 함수
def refresh_access_token(request):
    # 쿠키에서 Refresh Token 가져오기
    refresh_token = request.COOKIES.get("refresh_token")
    if not refresh_token:
        return JsonResponse({"status": 401, "message": "Refresh token not found"}, status=401)

    # 구글 OAuth 서버에 액세스 토큰 갱신 요청
    token_request = requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&grant_type=refresh_token&redirect_uri={GOOGLE_REDIRECT_URI}")

    # 토큰 응답 파싱
    token_data = token_request.json()
    new_access_token = token_data.get("access_token")
    new_id_token = token_data.get("id_token")

    if not new_access_token:
        return JsonResponse({"status": 401, "message": "Failed to refresh access token"}, status=401)

    # 새로운 액세스 토큰 반환
    return JsonResponse({
        "access_token": new_access_token,
        "id_token": new_id_token,
        "expires_in": token_data.get("expires_in"),
        "token_type": token_data.get("token_type"),
    }, status=200)

@permission_classes((IsAuthenticated, ))
def board_view(request):
    posts = Post.objects.all()
    return render(request, 'board.html', {'posts': posts})