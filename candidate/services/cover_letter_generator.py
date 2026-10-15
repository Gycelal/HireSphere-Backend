"""
Prepare cover-letter context and call the shared Gemini service.

Returns validated cover-letter data without saving it.
"""

import json
from .gemini_service import generate_structured_content
from .schemas import CoverLetterSchema
from .instructions import COVER_LETTER_GENERATOR_SYSTEM_INSTRUCTION

def generate_cover_letter(job_details: dict, resume_text: str) -> dict:

    if not resume_text.strip():
        raise ValueError("Resume text is required.")

    
    context = {
        "job": job_details,
        "resume": resume_text,
    }

    prompt = (
        "Write a cover letter for the supplied job using the reference data "
        "below. Return the result in the required JSON structure.\n\n"
        "REFERENCE DATA:\n"
        + json.dumps(context, ensure_ascii=False)
    )

    return generate_structured_content(
        prompt=prompt,
        system_instruction=COVER_LETTER_GENERATOR_SYSTEM_INSTRUCTION,
        schema=CoverLetterSchema,
        temperature=0.4,
    )