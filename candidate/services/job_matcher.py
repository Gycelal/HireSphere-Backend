from google import genai
from google.genai import types
from django.conf import settings
from schemas import AIAnalysisSchema
import json


def analyze_resume_job_mach(job_details: dict, resume_text: str) -> dict:

    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    job_context = f"""
    Title: {job_details.get('title')}
    Description: {job_details.get('description')}
    Skills Required: {job_details.get('skills_required')}
    Experience Required: {job_details.get('experience_required')}
    Responsibilities: {job_details.get('responsibilities')}
    """

    prompt = f"""
    You are an expert career counselor and recruiter helping a candidate evaluate their compatibility with a specific job role based on their resume.

    JOB SPECIFICATIONS:
    {job_context}

    CANDIDATE RESUME:
    {resume_text}

    Analyze the candidate's alignment with the job requirements.
    Be objective, accurate, and fair. Do not encourage fabricating experience.
    """

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GeneratedContentConfig(
            response_mime_type="application/json",
            response_schema=AIAnalysisSchema,
            temperature=0.2,
        ),
    )

    return json.loads(response.text)
