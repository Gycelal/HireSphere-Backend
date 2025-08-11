from django.db import models

class CompanyAdminApprovalStatus(models.TextChoices):
     PENDING = "pending", "Pending"
     APPROVED = "approved", "Approved"
     REJECTED = "rejected", "Rejected"