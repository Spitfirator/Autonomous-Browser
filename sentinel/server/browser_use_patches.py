"""Runtime patches applied to the vendored browser-use library.

We keep browser-use as an unmodified upstream checkout (its own git remote,
pulled/bumped independently), so anything Sentinel needs to change about its
behaviour is done here by monkeypatching public methods at startup instead of
editing OSS source — that way a `git pull` in ../browser-use never conflicts.

Currently this hides Sentinel's in-page control overlay from the agent.

The content script injects <sentinel-control id="__sentinel_root"> into every
page: the pulsing amber frame, the "Working on task / Take over" control pill,
and the invisible input shield. That overlay is the operator's UI, not part of
the website the agent is driving, so the model must never see it in the DOM /
accessibility tree or be able to target its buttons. (It still appears in raw
screenshots — that surface is shared with the human and can't be filtered
per-viewer without hiding the pill during capture, which we deliberately don't
do. Removing it from the DOM is what actually prevents the agent interacting
with it, since browser-use targets elements by their serialized index.)

browser-use builds a serialized DOM via a strict pipeline:

    DomService.get_serialized_dom_tree()
        -> get_dom_tree()            # builds the EnhancedDOMTreeNode tree
        -> DOMTreeSerializer(...)    # serializes + assigns interactive indices

So we wrap get_dom_tree and prune the overlay host — and its whole closed-shadow
subtree — from the tree before it is serialized. The serializer, clickable
detector, and selector map then all naturally exclude it.
"""

import logging

from browser_use.dom.service import DomService
from browser_use.dom.views import EnhancedDOMTreeNode

logger = logging.getLogger('sentinel.patches')

# Must match the host element created in extension/public/content.js.
SENTINEL_OVERLAY_ELEMENT_ID = '__sentinel_root'
SENTINEL_OVERLAY_TAG = 'sentinel-control'

_installed = False


def _is_sentinel_overlay(node: EnhancedDOMTreeNode) -> bool:
	"""True if this node is Sentinel's in-page control overlay host."""
	if node.tag_name == SENTINEL_OVERLAY_TAG:
		return True
	return (node.attributes or {}).get('id') == SENTINEL_OVERLAY_ELEMENT_ID


def _prune_overlay(node: EnhancedDOMTreeNode | None) -> None:
	"""Recursively drop the overlay host from a tree in place.

	Removing the host removes its whole subtree with it (its closed shadow root
	hangs off the host), so we only ever need to filter the child/shadow lists.
	"""
	if node is None:
		return
	if node.children_nodes:
		node.children_nodes = [c for c in node.children_nodes if not _is_sentinel_overlay(c)]
		for child in node.children_nodes:
			_prune_overlay(child)
	if node.shadow_roots:
		node.shadow_roots = [s for s in node.shadow_roots if not _is_sentinel_overlay(s)]
		for shadow in node.shadow_roots:
			_prune_overlay(shadow)
	if node.content_document:
		_prune_overlay(node.content_document)


def install() -> None:
	"""Install the browser-use patches. Idempotent; call once at startup."""
	global _installed
	if _installed:
		return

	# Fail loudly at startup (not silently at runtime) if upstream renamed the
	# method we hook — better a crash on boot than the pill silently reappearing.
	original_get_dom_tree = DomService.get_dom_tree

	async def get_dom_tree(self: DomService, *args, **kwargs):
		root, timing = await original_get_dom_tree(self, *args, **kwargs)
		_prune_overlay(root)
		return root, timing

	get_dom_tree.__wrapped__ = original_get_dom_tree  # type: ignore[attr-defined]
	DomService.get_dom_tree = get_dom_tree  # type: ignore[method-assign]

	_installed = True
	logger.info('browser-use patches installed (Sentinel overlay hidden from agent DOM)')
