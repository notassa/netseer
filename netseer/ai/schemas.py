"""LLM output contract (CONCEPTS A7): the JSON every explanation must match."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Cited(BaseModel):
    """A statement with the evidence (E#) or knowledge (K#) IDs that support it."""

    text: str
    refs: list[str] = Field(min_length=1, max_length=4)


class Action(BaseModel):
    """A recommended action, why it helps, and its supporting IDs."""

    action: str
    reason: str
    refs: list[str] = Field(min_length=1, max_length=4)


class ExplainOutput(BaseModel):
    """One plain-language explanation of a possible incident."""

    summary: str
    what_happened: str
    why_it_matters: str
    risk_explanation: str
    uncertainty: str
    recommended_actions: list[Action] = Field(min_length=1, max_length=5)
    claims: list[Cited] = Field(min_length=1, max_length=6)


TEXT_FIELDS = ("summary", "what_happened", "why_it_matters", "risk_explanation", "uncertainty")
