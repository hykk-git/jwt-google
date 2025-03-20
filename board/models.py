from django.db import models
from django.contrib.auth.models import User

class Post(models.Model):
    # 게시글 객체
    title = models.CharField(max_length=100)
    content = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

