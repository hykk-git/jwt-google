from pathlib import Path
import os

from django.shortcuts import redirect, render
from rest_framework import status
from django.http import JsonResponse
from allauth.socialaccount.models import SocialAccount
import requests

from .models import *

GOOGLE_USERINFO_SCOPE = os.getenv("GOOGLE_SCOPE_USERINFO")
GOOGLE_LOGIN_PAGE = os.getenv("GOOGLE_LOGIN_PAGE")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_SECRET = os.getenv("GOOGLE_SECRET")

# 메인 페이지
def main_view(request):
    return render(request, 'main.html')

# 로그인 페이지 연결
def google_login(request):
   # 로그인에 사용할 정보의 범위 설정(이번에는 email만)
   scope = GOOGLE_USERINFO_SCOPE

   # Google 로그인 페이지를 띄워 주는 역할
   return redirect(f"{GOOGLE_LOGIN_PAGE}?client_id={GOOGLE_CLIENT_ID}&response_type=code&redirect_uri={GOOGLE_CALLBACK_URI}&scope={scope}")

# 인가 코드를 받아 로그인 처리
def google_callback(request):
    # JS에서 인가 코드 받아옴
    code = request.GET.get("code")
    
    # 발급받은 Client ID, SECRET, 받은 인가 코드로 token 요청
    token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}")

    # 토큰 응답은 JSON으로 옴->data.get으로 JSON 파싱
    google_access_token = token_request.data.get('access_token')
    google_refresh_token = token_request.data.get('refresh_token')

    # 발급받은 access token으로 리소스 서버에 사용자 이메일 정보 요청
    email_response = requests.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={google_access_token}")

    if email_response.status_code != 200:
        return JsonResponse({"status": 400,"message": "Bad Request"}, status=status.HTTP_400_BAD_REQUEST)

    email = email_response.data.get('email')

    try:
        # 기존 유저 이메일과 같은지 확인
        user = User.objects.get(email=email)
        
        # 만약 계정이 없으면 회원가입 진행
        if user is None:
            user = User.objects.create(
            email=email,
            username=email.split('@')[0],  # 이메일 앞부분을 username으로 설정
        )
        user.set_unusable_password()  # 비밀번호 설정 불가로 처리
        user.save()

        # 소셜로그인 계정 유무 확인(Google이 맞는지)
        social_user = SocialAccount.objects.get(user=user)
        
        if social_user.provider != "google":
            return JsonResponse({"status": 400,"message": "User Account Not Exists"}, status=status.HTTP_400_BAD_REQUEST) 
		
        res = JsonResponse(
                {
                    "user": {
                        "id": user.id,
                        "email": user.email,
                    },
                    "message": "login success",
                    "token": {
                        "access_token": google_access_token,
                        "refresh_token": google_refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
        return res
        
    except: 
        return JsonResponse({"status": 400,"message": "Serializer Errors"}, status=status.HTTP_400_BAD_REQUEST)