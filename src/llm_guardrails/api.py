from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .scanner import GuardrailEngine


app = FastAPI(title="LLM Guardrails", version="0.1.0")
engine = GuardrailEngine()


class InputRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


class OutputRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    canary: str | None = Field(default=None, max_length=200)
    redact: bool = True


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan/input")
def scan_input(request: InputRequest) -> dict[str, object]:
    return engine.scan_input(request.text).to_dict()


@app.post("/v1/scan/output")
def scan_output(request: OutputRequest) -> dict[str, object]:
    try:
        return engine.scan_output(request.text, request.canary, request.redact).to_dict()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

