from django_filters import FilterSet, CharFilter
from .models import Job

class JobFilter(FilterSet):
    location = CharFilter(lookup_expr="icontains")

    class Meta:
        model = Job
        fields =[
            "employment_type",
            "location",
            "work_mode",
            "experience_required"
        ]