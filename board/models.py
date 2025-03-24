from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    # email이 기본키인 커스텀 유저 모델
    email = models.EmailField(unique=True, primary_key=True)
    name = models.CharField(max_length=50)

    USERNAME_FIELD = 'email'  # 기본 로그인 필드 설정
    REQUIRED_FIELDS = ['name']  # 필수 필드
    
    def __str__(self):
        return self.name

class Post(models.Model):
    # 게시글 객체
    title = models.CharField(max_length=100)
    content = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

