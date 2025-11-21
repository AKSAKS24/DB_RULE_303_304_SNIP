from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="Rule 303 & 304 — SET EXTENDED CHECK + BREAK-POINT Scanner",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
RULE_303 = "Remove obsolete SET EXTENDED CHECK statement"
RULE_304 = "BREAK-POINT is not allowed in ABAP for Cloud / Key User scenarios"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Regex patterns (extended to catch all syntax variants)
# ---------------------------------------------------------------------------
SET_EXT_CHECK_RE = re.compile(
    r"\bSET\s+EXTENDED\s+CHECK\b", re.IGNORECASE
)

# capture BREAK-POINT, BREAK-POINT ID, BREAK-POINT <var>, BREAK-POINT .
BREAKPOINT_RE = re.compile(
    r"\bBREAK-POINT\b(?:\s+\w+)?", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def extract_line(text: str, pos: int) -> str:
    """Return EXACT affected line only."""
    line_start = text.rfind("\n", 0, pos)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def make_finding(unit: Unit, src: str, start: int, end: int,
                 issue: str, message: str, suggestion: str) -> Finding:

    line_in_block = src.count("\n", 0, start) + 1
    abs_start = unit.start_line + line_in_block
    abs_end = abs_start

    snippet = extract_line(src, start).replace("\n", "\\n")

    return Finding(
        prog_name=unit.pgm_name,
        incl_name=unit.inc_name,
        types=unit.type,
        blockname=unit.name,
        starting_line=abs_start,
        ending_line=abs_end,
        issues_type=issue,
        severity="error",
        message=message,
        suggestion=suggestion,
        snippet=snippet,
    )


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    fnds: List[Finding] = []

    # ---------------- Rule 303 ----------------
    for m in SET_EXT_CHECK_RE.finditer(src):
        stmt = m.group(0)
        msg = "Obsolete SET EXTENDED CHECK statement detected."
        sug = "Remove the SET EXTENDED CHECK statement entirely."
        fnds.append(
            make_finding(
                unit, src, m.start(), m.end(),
                "Rule303_SetExtendedCheck", msg, sug
            )
        )

    # ---------------- Rule 304 ----------------
    for m in BREAKPOINT_RE.finditer(src):
        stmt = m.group(0)
        msg = "BREAK-POINT is not allowed in ABAP Cloud / Key User scenarios."
        sug = "Remove or comment out the BREAK-POINT statement."
        fnds.append(
            make_finding(
                unit, src, m.start(), m.end(),
                "Rule304_BreakPointUsage", msg, sug
            )
        )

    out = Unit(**unit.model_dump())
    out.findings = fnds if fnds else None
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_array(units: List[Unit] = Body(...)):
    results = []
    for u in units:
        scanned = scan_unit(u)
        if scanned.findings:
            results.append(scanned)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rules": [303, 304], "version": "2.0"}
