from pydantic import BaseModel, Field
from typing import List


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