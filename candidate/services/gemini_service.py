import logging
import time
import random
import httpx

from pydantic import BaseModel, ValidationError
from google import genai
from google.genai import types
from django.conf import settings
from google.genai.errors import APIError

logger = logging.getLogger(__name__)
models_to_try = ["gemini-3.6-flash", "gemini-3.5-flash", "gemini-3.5-flash-lite"]


BLOCKED_FINISH_REASONS = {
    "SAFETY",
    "RECITATION",
    "BLOCKLIST",
    "PROHIBITED_CONTENT",
    "SPII",
    "IMAGE_SAFETY",
    "IMAGE_PROHIBITED_CONTENT",
    "IMAGE_RECITATION",
}



class AIServiceError(Exception):
    """Custom exception to indicate that the AI service is unavailable after retries."""


class AIResponseBlockedError(AIServiceError):
    """Custom exception to indicate that the AI service provider blocked the request or the response."""


def _enum_value(value):
    return getattr(value, "value", value)


def _validate_response(response, schema: type[BaseModel]) -> dict:
    feedback = response.prompt_feedback

    if feedback:
        block_reason = _enum_value(feedback.block_reason)

        if block_reason not in (
            None,
            "BLOCK_REASON_UNSPECIFIED",
        ):
            raise AIResponseBlockedError("The AI service blocked this request.")

    for candidate in response.candidates or []:
        reason = _enum_value(candidate.finish_reason)

        if reason in BLOCKED_FINISH_REASONS:
            raise AIResponseBlockedError(
                f"The AI response was blocked: {reason}."
            )

        if reason == "MAX_TOKENS":
            raise ValueError("The AI response was truncated due to token limits.")

        if reason != "STOP":
            raise ValueError(
                f"The AI response did not finish normally: {reason}."
            )

    if not response.text:
        raise ValueError("The AI response was empty.")

    result = schema.model_validate_json(response.text)

    return result.model_dump()


def generate_structured_content(
    *,
    prompt: str,
    system_instruction: str,
    schema: type[BaseModel],
    temperature: float,
) -> dict:
    """Call Gemini with bounded retries, fallback and validation."""

    model_names = models_to_try

    if not model_names:
        raise ValueError("At least one Gemini model is required.")

    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        response_mime_type="application/json",
        response_schema=schema,
        temperature=temperature,
    )

    client = genai.Client(
        api_key=settings.GEMINI_API_KEY,
        http_options=types.HttpOptions(
            timeout=20_000,
            retry_options=types.HttpRetryOptions(attempts=1)
        )
    )

    total_calls = 0
    last_error = None
    RETRYABLE_STATUS_CODES = {500, 502, 503, 504}
    MAX_TOTAL_CALLS = 5
    MAX_ATTEMPTS_PER_MODEL = 2

    try:
        for model_name in model_names:

            for attempt in range(MAX_ATTEMPTS_PER_MODEL):
                if total_calls >= MAX_TOTAL_CALLS:
                    raise AIServiceError(
                        "AI request attempt limit reached."
                    ) from last_error

                total_calls += 1

                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=config,
                    )
                    
                except APIError as e:
                    last_error = e

                    logger.warning(
                        "Gemini API failure: model=%s status=%s",
                        model_name,
                        e.code,
                    )

                    if e.code == 429:
                        # Quota might not recover during this request, so we should not retry.
                        break

                    if e.code not in RETRYABLE_STATUS_CODES:
                        # Configuration/request errors need fixing.
                        raise

                    if (attempt == 0 and total_calls < MAX_TOTAL_CALLS):
                        time.sleep(1.0 + random.uniform(0, 0.5))
                        continue

                    break

                except httpx.TimeoutException as exc:
                    last_error = exc

                    logger.warning(
                        "Gemini transport failure: model=%s type=%s",
                        model_name,
                        type(exc).__name__
                    )
                    break

                # seperate output validation
                try:
                    data = _validate_response(response, schema)
                    print(data)
                    return data

                except AIResponseBlockedError:
                    raise
                except(ValidationError, ValueError) as exc:
                    last_error = exc

                    logger.warning(
                        "Gemini output validation failed: model=%s",
                        model_name,
                    )
                    break
        raise AIServiceError(
            "No configured model returned a usable response."
        ) from last_error

    finally:
        client.close()

                            


                        

