
"""
AI Resume-Job Matcher Serivice.

Handles candidate resume analysis against job specifications using Google's GenAi SDK.
It has multiple model fallback srategies to guarantee high availability against 503 servuce 
unavailable spikes and handles model-level exceptions safely, returning a 503 to the client when all models fail.
"""



from google import genai
from google.genai import types
from django.conf import settings
from .schemas import AIAnalysisSchema
import json
from google.genai.errors import APIError

import logging
logger = logging.getLogger(__name__)


def analyze_resume_job_match(job_details: dict, resume_text: str) -> dict:

    client = genai.Client(api_key=settings.GEMINI_API_KEY)
    
    job_context = f"""
    Title: {job_details["title"]}
    Description: {job_details["description"]}
    Skills Required: {job_details["skills_required"]}
    Experience Required: {job_details["experience_required"]}
    Responsibilities: {job_details["responsibilities"]}
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

    config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=AIAnalysisSchema,
            temperature=0.2
    )

    models_to_try = ["gemini-3.6-flash", "gemini-3.5-flash", "gemini-3.5-flash-lite"]

    last_exception = None

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=config,
            )
            return json.loads(response.text)
        except (APIError, json.JSONDecodeError) as e:
            logger.warning(f"Model {model_name} failed: {e}. Moving to next fallback.")
            last_exception = e
    raise last_exception
