"""Sentinel entrypoint. Run from the sentinel/ directory:

    uv run --project ../browser-use --no-sync python -m server.main

(start.sh does exactly this, building the extension first if needed.)
Environment toggles: SENTINEL_PORT (default 8765), SENTINEL_NO_BROWSER=1 to
skip launching Chrome (API-only, for development/tests).
"""

import asyncio
import logging
import os
import signal

from dotenv import load_dotenv

from server.config import BASE_URL, DATA_DIR, ENV_FILE, HISTORY_FILE, HOST, PORT, ConfigStore

# Load API keys from browser-use/.env before importing anything that reads them,
# and keep browser-use's telemetry off by default.
load_dotenv(ENV_FILE)
os.environ.setdefault('ANONYMIZED_TELEMETRY', 'false')

from aiohttp import web  # noqa: E402

from server.api import build_app  # noqa: E402
from server.browser import BrowserManager  # noqa: E402
from server.browser_use_patches import install as install_browser_use_patches  # noqa: E402
from server.events import EventHub  # noqa: E402
from server.governance import ApprovalManager, HandoverManager, PolicyEngine  # noqa: E402
from server.history import HistoryStore  # noqa: E402
from server.runner import AgentRunner  # noqa: E402

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-7s %(name)s  %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger('sentinel')


async def main() -> None:
	DATA_DIR.mkdir(parents=True, exist_ok=True)

	# Patch the vendored browser-use before any Agent builds a DOM (hides
	# Sentinel's own in-page control overlay from the agent). See the module.
	install_browser_use_patches()

	config_store = ConfigStore()
	hub = EventHub()
	approvals = ApprovalManager(hub.emit)
	handovers = HandoverManager(hub.emit)
	policy = PolicyEngine(config_store)
	history = HistoryStore(HISTORY_FILE)
	browser_manager = BrowserManager(config_store)
	runner = AgentRunner(config_store, hub, policy, approvals, handovers, browser_manager, history)
	hub.status_provider = runner.status_dict

	app = build_app(config_store, hub, runner, approvals, handovers, browser_manager, history)
	app_runner = web.AppRunner(app)
	await app_runner.setup()
	site = web.TCPSite(app_runner, HOST, PORT)
	await site.start()
	logger.info(f'Sentinel listening on {BASE_URL}')

	browser_task: asyncio.Task | None = None
	if os.environ.get('SENTINEL_NO_BROWSER') != '1':

		async def start_browser() -> None:
			try:
				await browser_manager.start()
			except Exception:
				logger.exception('Browser launch failed — API still up; fix and restart')

		browser_task = asyncio.create_task(start_browser())
	else:
		logger.info('SENTINEL_NO_BROWSER=1 — skipping Chrome launch')

	stop_event = asyncio.Event()
	loop = asyncio.get_running_loop()
	for sig in (signal.SIGINT, signal.SIGTERM):
		loop.add_signal_handler(sig, stop_event.set)

	await stop_event.wait()
	logger.info('Shutting down (Chrome window stays open — keep_alive) ...')
	if browser_task is not None:
		browser_task.cancel()
	await runner.shutdown()
	approvals.cancel_all()
	handovers.cancel_all()
	await app_runner.cleanup()


if __name__ == '__main__':
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		pass
