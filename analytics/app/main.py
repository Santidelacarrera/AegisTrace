from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .detectors import detect

app = FastAPI(title="AegisTrace analytics", version="0.1.0")

MAX_EVENTS = 20000


class Event(BaseModel):
    id: str = Field(max_length=64)
    timestamp: str = Field(max_length=40)
    type: str = Field(max_length=64)
    user: str | None = Field(default=None, max_length=256)
    ip: str | None = Field(default=None, max_length=64)


class AnomalyRequest(BaseModel):
    events: list[Event] = Field(max_length=MAX_EVENTS)


class Anomaly(BaseModel):
    kind: str
    subject: str
    score: float
    eventIds: list[str]
    explanation: str


class AnomalyResponse(BaseModel):
    anomalies: list[Anomaly]
    analyzed: int


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/anomalies", response_model=AnomalyResponse)
def anomalies(req: AnomalyRequest) -> AnomalyResponse:
    events = [e.model_dump() for e in req.events]
    return AnomalyResponse(anomalies=[Anomaly(**a) for a in detect(events)], analyzed=len(events))
