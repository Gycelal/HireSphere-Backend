from rest_framework.exceptions import APIException

class AlreadyApplied(APIException):
    status_code = 409
    default_detail = "You have already applied for this job."
    default_code = "already_applied"
    