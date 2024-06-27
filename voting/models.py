# voting/models.py
from django.db import models

class Election(models.Model):
    name = models.CharField(max_length=255)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()

    def __str__(self):
        return self.name

class Candidate(models.Model):
    name = models.CharField(max_length=255)
    candidate_number = models.IntegerField()
    description = models.TextField()
    slogan = models.TextField()
    photo = models.BinaryField(blank=True, null=True)
    video = models.BinaryField(blank=True, null=True)
    status = models.CharField(max_length=50, default='pending')  # pending, approved, rejected
