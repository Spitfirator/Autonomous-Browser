"""BrowserManager: dedicated Chrome window + extension-install ladder.

Launch strategy:
- Reconnect to a still-running Sentinel Chrome from a previous server run if its
  CDP endpoint (saved in data/browser.json) still answers — keep_alive means we
  deliberately leave Chrome up when the server exits.
- Otherwise launch the user's real Chrome binary with the dedicated persistent
  profile (marker dir name — see server/config.py) via browser-use's local path.

Extension install ladder (branded Chrome >=137 ignores --load-extension):
  1. --load-extension arg (works on Chromium/dev builds; free if ignored)
  2. liveness probe: /api/hello beacon or a chrome-extension:// CDP target
  3. CDP Extensions.loadUnpacked (documented pipe-only; attempted anyway, logged)
  4. navigate the window to our /setup page for the one-time manual Load unpacked
"""

import asyncio
import json
import logging
import time

import aiohttp
from browser_use import BrowserSession
from browser_use.skill_cli.utils import find_chrome_executable

from server.config import BASE_URL, BROWSER_STATE_FILE, EXTENSION_DIST, PROFILE_DIR, ConfigStore

logger = logging.getLogger('sentinel.browser')

_EXTRA_ALLOWED = ['127.0.0.1', 'localhost', 'chrome-extension://*']


def _allowed_domains(config_store: ConfigStore) -> list[str] | None:
	"""Mirror the policy allowlist into browser-use's SecurityWatchdog (defense in
	depth). PolicyEngine remains the authoritative live layer."""
	allowlist = config_store.get().policies.domain_allowlist
	if allowlist is None:
		return None
	return [*allowlist, *_EXTRA_ALLOWED]


class BrowserManager:
	def __init__(self, config_store: ConfigStore) -> None:
		self._config_store = config_store
		self.session: BrowserSession | None = None
		self.extension_seen_at: float = 0.0
		self.extension_id: str | None = None
		self._started_at: float = 0.0

	@property
	def status(self) -> str:
		return 'running' if self.session is not None else 'stopped'

	@property
	def extension_seen(self) -> bool:
		return self.extension_seen_at > 0

	def mark_extension_seen(self, extension_id: str | None) -> None:
		self.extension_seen_at = time.time()
		if extension_id:
			self.extension_id = extension_id
			config = self._config_store.get()
			if config.pinned_extension_id is None:
				self._config_store.update({'pinned_extension_id': extension_id})
				logger.info(f'Pinned extension id {extension_id}')

	# ── Launch ───────────────────────────────────────────────────────────────
	async def start(self) -> None:
		self._started_at = time.time()
		session = await self._reconnect() or await self._launch()
		self.session = session
		self._save_state()
		logger.info(f'Browser ready (cdp_url={session.cdp_url})')
		await self._ensure_extension()

	async def _reconnect(self) -> BrowserSession | None:
		if not BROWSER_STATE_FILE.exists():
			return None
		try:
			cdp_url = json.loads(BROWSER_STATE_FILE.read_text()).get('cdp_url')
		except (json.JSONDecodeError, OSError):
			return None
		if not cdp_url:
			return None
		probe = cdp_url.rstrip('/')
		if probe.startswith('ws'):
			probe = 'http' + probe[2:]
		try:
			async with aiohttp.ClientSession() as http:
				async with http.get(f'{probe}/json/version', timeout=aiohttp.ClientTimeout(total=1.5)) as resp:
					if resp.status != 200:
						return None
		except Exception:
			return None
		logger.info(f'Reconnecting to existing Sentinel Chrome at {cdp_url}')
		try:
			session = BrowserSession(cdp_url=cdp_url, is_local=True, keep_alive=True)
			await session.start()
			return session
		except Exception as e:
			logger.warning(f'Reconnect failed, launching fresh: {e}')
			return None

	async def _launch(self) -> BrowserSession:
		PROFILE_DIR.mkdir(parents=True, exist_ok=True)
		executable = find_chrome_executable()
		logger.info(f'Launching dedicated Chrome: {executable}')
		session = BrowserSession(
			executable_path=executable,
			user_data_dir=PROFILE_DIR,
			headless=False,
			keep_alive=True,
			enable_default_extensions=False,
			allowed_domains=_allowed_domains(self._config_store),
			args=[
				f'--load-extension={EXTENSION_DIST}',       # rung 1 (ignored by branded Chrome >=137)
				'--enable-unsafe-extension-debugging',      # prerequisite for rung 3
				'--no-first-run',
				'--no-default-browser-check',
			],
		)
		await session.start()
		return session

	def _save_state(self) -> None:
		try:
			BROWSER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
			BROWSER_STATE_FILE.write_text(json.dumps({'cdp_url': self.session.cdp_url if self.session else None}))
		except OSError as e:
			logger.warning(f'Could not persist browser state: {e}')

	# ── Extension install ladder ─────────────────────────────────────────────
	async def _ensure_extension(self) -> None:
		if await self._probe_extension(timeout_s=10):
			logger.info('Sentinel extension detected — no install needed')
			return

		# Rung 3: CDP Extensions.loadUnpacked (documented as pipe-transport-only;
		# we connect over websocket, so expect failure on branded Chrome — but it
		# is one call and works on some builds).
		try:
			assert self.session is not None
			await self.session.cdp_client.send.Extensions.loadUnpacked(params={'path': str(EXTENSION_DIST)})
			logger.info('Extensions.loadUnpacked succeeded')
		except Exception as e:
			logger.info(f'Extensions.loadUnpacked not available (expected on branded Chrome): {e}')

		if await self._probe_extension(timeout_s=3):
			logger.info('Sentinel extension loaded via CDP')
			return

		# Rung 4: one-time manual install. The setup page shows exact steps and
		# flips green once the extension's /api/hello beacon lands. The unpacked
		# extension persists in the dedicated profile, so this happens once ever.
		logger.info('Opening setup page for one-time manual extension install')
		try:
			assert self.session is not None
			await self.session.navigate_to(f'{BASE_URL}/setup')
		except Exception as e:
			logger.warning(f'Could not open setup page automatically: {e} — open {BASE_URL}/setup manually')

	async def _probe_extension(self, timeout_s: float) -> bool:
		deadline = time.monotonic() + timeout_s
		while time.monotonic() < deadline:
			if self.extension_seen_at >= self._started_at:
				return True
			if await self._has_extension_target():
				self.extension_seen_at = time.time()
				return True
			await asyncio.sleep(1)
		return False

	async def _has_extension_target(self) -> bool:
		if self.session is None:
			return False
		try:
			result = await self.session.cdp_client.send.Target.getTargets()
			for target in result.get('targetInfos', []):
				url = target.get('url', '')
				if url.startswith('chrome-extension://') and (
					self.extension_id is None or self.extension_id in url
				):
					# Any extension target counts: this profile only ever gets ours
					# (default extensions are disabled).
					return True
		except Exception:
			pass
		return False

	def refresh_allowed_domains(self) -> None:
		"""Mirror live policy edits into the running session's SecurityWatchdog."""
		if self.session is not None:
			try:
				self.session.browser_profile.allowed_domains = _allowed_domains(self._config_store)
			except Exception as e:
				logger.warning(f'Could not update allowed_domains live: {e}')
