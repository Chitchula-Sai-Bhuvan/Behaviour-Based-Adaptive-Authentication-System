"""
api/pages.py
─────────────
HTML page routes — serve Jinja2 templates for the browser-based UI.

Routes:
  GET /           → login page
  GET /register   → registration page
  GET /mfa        → MFA approval page
  GET /dashboard  → risk score + log viewer dashboard
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

router = APIRouter(tags=["UI Pages"])

# Resolve templates directory relative to this file's location
_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(_base, "templates"))


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.get("/mfa", response_class=HTMLResponse, include_in_schema=False)
def mfa_page(request: Request):
    return templates.TemplateResponse("mfa.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
