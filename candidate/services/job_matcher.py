"""
AI Resume-Job Matcher Serivice.

Handles candidate resume analysis against job specifications using Google's GenAi SDK.
It has multiple model fallback srategies to guarantee high availability against 503 servuce
unavailable spikes and handles model-level exceptions safely, returning a 503 to the client when all models fail.
"""

from .gemini_service import generate_structured_content
from .schemas import AIAnalysisSchema
from .instructions import JOB_MATCHER_SYSTEM_INSTRUCTION

import logging

logger = logging.getLogger(__name__)


def analyze_resume_job_match(job_details: dict, resume_text: str) -> dict:

    job_context = f"""
    Title: {job_details["title"]}
    Description: {job_details["description"]}
    Skills Required: {job_details["skills_required"]}
    Experience Required: {job_details["experience_required"]}
    Responsibilities: {job_details["responsibilities"]}
    """
    prompt = f"""
        Analyze the candidate's alignment with the following job requirements.

        JOB SPECIFICATIONS:
        {job_context}

        CANDIDATE RESUME:
        {resume_text}

        Provide:
        - An overall match score based on relevant skills, experience, and projects.
        - Matching strengths supported by the resume.
        - Gaps or requirements not demonstrated in the resume.
        - Actionable suggestions to improve alignment without inventing qualifications.

        Return the analysis in the required JSON structure.
            """

    return generate_structured_content(
        prompt=prompt,
        system_instruction=JOB_MATCHER_SYSTEM_INSTRUCTION,
        schema=AIAnalysisSchema,
        temperature=0.2,
    )
