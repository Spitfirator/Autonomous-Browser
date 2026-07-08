"""Sentinel — control plane and enforcement middleware for browser-use.

Runs a local aiohttp server (REST + WebSocket) that launches a dedicated Chrome
window, drives browser-use Agents against it, and streams every step, LLM call,
and enforcement decision to the Sentinel Chrome extension (side panel + dashboard).
"""
