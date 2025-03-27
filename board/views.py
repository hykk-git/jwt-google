from pathlib import Path

import os
import hashlib
import requests

# id 검증에 필요한 google 패키지
from google.oauth2 import id_token
from google.auth.transport.requests import Request

from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseRedirect
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.decorators import api_view

# django에서 소셜 계정을 관리하는 모델
from allauth.socialaccount.models import SocialAccount

from .models import *
from .forms import SignupForm

# .env 파일을 읽어서 현재 환경 변수로 로드하는 패키지
from dotenv import load_dotenv

# .env 파일에 있는 값들을 os.environ 딕셔너리에 추가
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Google OAuth 환경변수 설정(없을 경우 None 반환)
GOOGLE_USERINFO_SCOPE = os.getenv("GOOGLE_USERINFO_SCOPE")
GOOGLE_LOGIN_PAGE = os.getenv("GOOGLE_LOGIN_PAGE")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_REFRESH_TOKEN")

# 메인화면
def main_view(request):
    return render(request, 'main.html')

# 일반 회원가입
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

# httponly, secure = True로 token을 쿠키에 저장하는 함수
def set_cookies(response, access_token, refresh_token):
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # 개발시에만 False
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False, 
        samesite="None"
    )
    return response

# 일반 회원가입 사용자 로그인
def login_view(request):
    return render(request, 'login.html')

# 구글 로그인 페이지 연결
def google_login(request):
   # 위조 방지 토큰, nonce 생성
   state = hashlib.sha256(os.urandom(1024)).hexdigest()
   nonce = hashlib.sha256(os.urandom(1024)).hexdigest()
   request.session['state'] = state
   request.session['nonce'] = nonce

   print("처음 state: ", request.session.get('state'))
   print("처음 nonce: ", request.session.get('nonce'))
   # Google 로그인 페이지를 띄워 주는 역할
   google_auth_request = (
        f"{GOOGLE_LOGIN_PAGE}"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&scope=openid%20email%20profile"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={state}"
        f"&nonce={nonce}"
    )
   return redirect(google_auth_request)

# 인가 코드를 받아 로그인 처리
def google_callback(request):
    # 프론트에서 인가 코드 받아옴
    code = request.GET.get("code")
    state = request.GET.get("state")

    print("get으로 넘어온 state: ", state)
    print("state: ", request.session.get('state'))
    # 발급받은 Client ID, SECRET, 받은 인가 코드로 리소스 서버에 token 요청
    token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}")

    # 토큰 응답은 JSON으로 옴->json()으로 파싱
    token_data = token_request.json()

    google_access_token = token_data.get('access_token')
    google_refresh_token = token_data.get('refresh_token')
    google_id_token = token_data.get('id_token')

    # state(위조 방지 토큰) 유효성 검증
    if not state or state != request.session.get('state'):
        return JsonResponse({'error': 'Invalid state parameter.'}, status=401)

    # state는 삭제 권장한다 함
    del request.session['state']

    # ID 토큰 유효성 검증
    # input: id token, client_id
    # output: 디코딩돼서 검증된 id token
    verified_token = id_token.verify_oauth2_token(
        google_id_token,
        Request(),
        GOOGLE_CLIENT_ID,
    )

    print("검증된 id 토큰:", verified_token)
    # ID 토큰에서 사용자 정보 가져옴
    email = verified_token.get('email')
    name = verified_token.get('name') # 없을 경우 none

    user = User.objects.filter(email=email).first()

    # 인증된 사용자의 회원가입 여부와 방법 확인
    if user:
        if not SocialAccount.objects.filter(user=user, provider="google").exists():
            # 기존에 일반 회원가입 유저인 경우 소셜 계정을 추가해야 함
            SocialAccount.objects.create(user=user, provider="google", uid=email)

    # 기존에 회원가입하지 않은 유저 → 가입 여부 묻기
    else:
        # 회원가입 진행(소셜 계정 추가)
        user = User.objects.create_user(email=email, name=name)
        SocialAccount.objects.create(user=user, provider="google", uid=email)

    # 로그인 처리(토큰 발급 후 main 이동)
    app_refresh_token = RefreshToken.for_user(user)
    app_access_token = app_refresh_token.access_token

    response = HttpResponseRedirect("/")
    response = set_cookies(response, app_access_token, app_refresh_token)
    return response

# 쿠키로 현재 로그인 상태를 확인하고 'login'을 Boolean으로 반환하는 함수
@api_view(['GET'])
def login_status(request):
    access_token = request.COOKIES.get('access_token')
    if access_token:
        return JsonResponse({"login": True, "message": "로그인 상태"})
    else:
        return JsonResponse({"login": False, "message": "로그아웃 상태"})

# 요청을 받고 브라우저 쿠키를 비활성화시키는 로그아웃 함수
@api_view(['POST'])
def logout_view(request):
    response = JsonResponse({"status": 200, "message": "로그아웃 되었습니다."})
    
    # 쿠키 삭제 (쿠키 유효기간 과거로 설정)
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response

# Googe Refresh Token을 받아서 Access Token을 갱신하는 함수
def refresh_access_token(refresh_token):
    try:
        # grant type을 refresh_token으로 설정
        token_request= requests.post(f"https://oauth2.googleapis.com/token?client_id={GOOGLE_CLIENT_ID}&client_secret={GOOGLE_CLIENT_SECRET}&grant_type=refresh_token&refresh_token={refresh_token}")
        token_data = token_request.json()
        google_access_token = token_data.get('google_access_token')
        return google_access_token
    except Exception as e:
        print(f"토큰 갱신 오류: {str(e)}")
        return None

# Google Access Token 갱신 API
def refresh_token_view(request):
    refresh_token = request.COOKIES.get("google_refresh_token")
    if not refresh_token:
        return JsonResponse({"status": 401, "message": "Refresh token not found"}, status=401)

    new_access_token = refresh_access_token(refresh_token)
    if not new_access_token:
        return JsonResponse({"status": 401, "message": "Token refresh failed"}, status=401)

    # 새로운 Access Token 설정
    response = JsonResponse({"status": 200, "message": "Token refreshed"})
    response.set_cookie(
        key="google_access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="Lax"
    )
    return response

# 쿠키 여부를 확인하고 인가된 사용자만 보여 주는 게시판 화면
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