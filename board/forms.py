from django import forms
from django.contrib.auth.models import User
from .models import Post

class SignupForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)  # 비밀번호 필드 (암호화됨)

    class Meta:
        model = User  # Django 내장 User 모델과 연결
        fields = ['username', 'email', 'password']  # 필요한 필드 선택


class PostForm(forms.ModelForm):
    class Meta:
        model = Post  # 게시판의 Post 모델과 연결
        fields = ['title', 'content']  # 제목과 내용 필드만 사용
        
        