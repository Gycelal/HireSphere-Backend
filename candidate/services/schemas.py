"""
Pydantic schemas for AI-driven resume matching responses.

Defines the structured JSON output schema enforced during Google Gemini 
API generation calls for candidate job alignment.
"""

from pydantic import BaseModel, Field, model_validator
from typing import List, Literal


class AIAnalysisSchema(BaseModel):
    match_score: int = Field(
        ..., ge=0, le=100, description="Overall match percentage score between 0 and 100 based on technical skill, experience, project match between resume and job requirements."
    )
    matching_strengths: List[str] = Field(
        ..., description="3 to 5 key matching skills or relevant experiences that align with the job"
    )
    gaps_identified: List[str] = Field(
        ..., description="2 to 4 missing requirements or skills that could be improved to better fit the job"
    )
    suggestions: List[str] = Field(
        ..., description="Actionable framing suggestions for the candidate to improve their resume and better align with the job"
    )


class CoverLetterSchema(BaseModel):
    cover_letter: str = Field(
        ...,
        description=(
            "Complete cover letter as plain text with paragraph breaks. "
            "No Markdown, commentary, or unfilled placeholders."
        )
    )

class CoverLetterAssistantResponseSchema(BaseModel):
    action: Literal["reply", "update"] = Field(
        description=(
            "'reply' for questions or explanations without changing the letter. "
            "'update' for creating or revising the cover letter."
        )
    )

    assistant_message: str = Field(
        min_length=1,
        max_length=1000,
        description="The message shown to the candidate in the chat panel."
    )

    updated_cover_letter: str | None = Field(
        description=(
            "The complete proposed cover letter for 'update'. "
            "Must be null for 'reply'."
        )
    )

    @model_validator(mode="after")
    def validate_response(self):
        if not self.assistant_message.strip():
            raise ValueError("assistant_message cannot be blank.")

        if self.action == "reply":
            if self.updated_cover_letter is not None:
                raise ValueError(
                    "updated_cover_letter must be null for 'reply'."
                )
        elif self.action == "update":
            letter = self.updated_cover_letter

            if letter is None or not letter.strip():
                raise ValueError(
                    "A non-empty updated_cover_letter is required for 'update'."
                )

            if len(letter) > 1500:
                raise ValueError(
                    "updated_cover_letter cannto exceed 1500 charecters."
                )
        return self

    