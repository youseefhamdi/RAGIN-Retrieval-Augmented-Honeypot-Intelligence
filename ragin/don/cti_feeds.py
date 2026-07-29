"""
Live CTI Feed Connectors for Don — pulls from MISP, AlienVault OTX,
and other sources in real time, then feeds into the ingestion pipeline.

Each connector is a thin async client that normalizes feed data into
the standard ``ThreatIntelDoc`` format expected by Don's existing
ingestion pipeline (``don.ingestion``).

Usage::

    from ragin.don.cti_feeds import CTIFeedManager

    manager = CTIFeedManager(misp_url="https://misp.local", otx_key="...")
    new_articles = await manager.fetch_all()
    # → List of ThreatIntelDoc, ready for don.ingestion.ingest()
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Normalized Feed Item ──────────────────────────────────────────────────────


@dataclass
class CTIFeedItem:
    """A single normalized CTI item from any feed source."""

    source: str
    title: str
    content: str
    url: str = ""
    published: str = ""
    tags: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def doc_id(self) -> str:
        return hashlib.sha256(f"{self.source}:{self.url or self.title}".encode()).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "source": self.source,
            "title": self.title,
            "content": self.content,
            "url": self.url,
            "published": self.published,
            "tags": self.tags,
            "iocs": self.iocs,
            "ttps": self.ttps,
            "fetched_at": self.fetched_at,
        }


# ── Abstract Base Connector ───────────────────────────────────────────────────


class CTIConnector(ABC):
    """Base class for CTI feed connectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable feed name."""

    @abstractmethod
    async def fetch(
        self,
        since: str = "",
        limit: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch recent items from this feed.

        Args:
            since: ISO timestamp — only fetch items newer than this.
            limit: Maximum items to fetch per call.
        """


# ── MISP Connector ────────────────────────────────────────────────────────────


class MISPConnector(CTIConnector):
    """Connects to a MISP instance and pulls recent threat events.

    Requires ``pymisp`` or ``aiohttp`` for HTTP communication.
    Falls back to direct REST API calls without pymisp dependency.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        ssl_verify: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._ssl_verify = ssl_verify

    @property
    def name(self) -> str:
        return "misp"

    async def fetch(
        self,
        since: str = "",
        limit: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch recent events from MISP."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not installed — MISP connector unavailable")
            return []

        items: list[CTIFeedItem] = []
        url = f"{self._base_url}/events/restSearch"
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Build search parameters
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["timestamp"] = since

        try:
            async with (
                aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=self._ssl_verify),
                ) as session,
                session.post(
                    url,
                    json=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp,
            ):
                if resp.status != 200:
                    logger.error("MISP API returned %d: %s", resp.status, await resp.text())
                    return []

                data = await resp.json()

            events = data.get("response", []) if isinstance(data, dict) else []
            for event_wrapper in events:
                event = event_wrapper.get("Event", event_wrapper)
                title = event.get("info", "Untitled MISP Event")
                tags = [t.get("name", "") for t in event.get("Tag", []) if t.get("name")]

                # Extract IOCs from attributes
                iocs: list[str] = []
                ttps: list[str] = []
                for attr in event.get("Attribute", []):
                    val = attr.get("value", "")
                    attr_type = attr.get("type", "")
                    if attr_type in ("ip-src", "ip-dst", "domain", "url", "md5", "sha256", "email-src"):
                        iocs.append(val)
                    if "mitre-attack" in attr_type.lower() or "attack-pattern" in attr_type.lower():
                        ttps.append(val)

                # Extract description
                content_parts = [title]
                if event.get("description"):
                    content_parts.append(event["description"])
                content_parts.extend(iocs[:20])  # include IOCs in content for embedding

                items.append(
                    CTIFeedItem(
                        source="misp",
                        title=title,
                        content="\n".join(content_parts),
                        url=f"{self._base_url}/events/view/{event.get('id', '')}",
                        published=event.get("date", ""),
                        tags=tags,
                        iocs=iocs,
                        ttps=ttps,
                        raw=event,
                    )
                )

            logger.info("Fetched %d events from MISP", len(items))

        except Exception as exc:
            logger.error("MISP fetch failed: %s", exc)

        return items


# ── AlienVault OTX Connector ─────────────────────────────────────────────────


class OTXConnector(CTIConnector):
    """Connects to AlienVault OTX and pulls recent pulses."""

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "otx"

    async def fetch(
        self,
        since: str = "",
        limit: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch recent pulses from OTX DirectConnect API."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not installed — OTX connector unavailable")
            return []

        items: list[CTIFeedItem] = []
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": self._api_key}

        params: dict[str, Any] = {"limit": min(limit, 50)}
        if since:
            params["modified_since"] = since

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp,
            ):
                if resp.status != 200:
                    logger.error("OTX API returned %d", resp.status)
                    return []

                data = await resp.json()

            pulses = data.get("results", []) if isinstance(data, dict) else []
            for pulse in pulses:
                title = pulse.get("name", "Untitled Pulse")
                tags = pulse.get("tags", [])
                description = pulse.get("description", "")

                # Extract IOCs from indicators
                iocs: list[str] = []
                ttps: list[str] = []
                for indicator in pulse.get("indicators", []):
                    ind_type = indicator.get("type", "")
                    ind_val = indicator.get("indicator", "")
                    if ind_type in ("IPv4", "IPv6", "domain", "URL", "FileHash-MD5", "FileHash-SHA256", "email"):
                        iocs.append(ind_val)
                    if "mitre" in ind_val.lower() or "attack-pattern" in ind_val.lower():
                        ttps.append(ind_val)

                # Kill chain phases → TTPs
                for kill_chain in pulse.get("kill_chain", []):
                    for phase in kill_chain.get("phases", []):
                        ttps.append(phase.get("phase_name", ""))

                content = f"{title}\n{description}\n" + "\n".join(iocs[:20])

                items.append(
                    CTIFeedItem(
                        source="otx",
                        title=title,
                        content=content,
                        url=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        published=pulse.get("created", ""),
                        tags=tags,
                        iocs=iocs,
                        ttps=ttps,
                        raw=pulse,
                    )
                )

            logger.info("Fetched %d pulses from OTX", len(items))

        except Exception as exc:
            logger.error("OTX fetch failed: %s", exc)

        return items


# ── RSS/Atom Feed Connector ──────────────────────────────────────────────────


class RSSConnector(CTIConnector):
    """Generic RSS/Atom feed connector for CTI blogs and advisories.

    Works with any standard RSS/Atom feed — NIST NVD, vendor advisories,
    CTI blogs, etc.
    """

    def __init__(self, feed_url: str, feed_name: str = "rss") -> None:
        self._feed_url = feed_url
        self._feed_name = feed_name

    @property
    def name(self) -> str:
        return self._feed_name

    async def fetch(
        self,
        since: str = "",
        limit: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch and parse RSS/Atom feed."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not installed — RSS connector unavailable")
            return []

        items: list[CTIFeedItem] = []

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(
                    self._feed_url,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp,
            ):
                if resp.status != 200:
                    logger.error("RSS feed returned %d: %s", resp.status, self._feed_url)
                    return []
                xml_text = await resp.text()

            # Simple XML parsing without external dependencies
            items = self._parse_feed_xml(xml_text, limit)

            logger.info("Fetched %d items from RSS: %s", len(items), self._feed_name)

        except Exception as exc:
            logger.error("RSS fetch failed (%s): %s", self._feed_url, exc)

        return items

    def _parse_feed_xml(self, xml_text: str, limit: int) -> list[CTIFeedItem]:
        """Minimal XML parsing for RSS/Atom feeds without lxml."""
        import re

        items: list[CTIFeedItem] = []

        # Detect RSS vs Atom
        is_atom = "<feed" in xml_text[:500].lower()

        if is_atom:
            entry_pattern = r"<entry[^>]*>(.*?)</entry>"
            title_pattern = r"<title[^>]*>(.*?)</title>"
            link_pattern = r'<link[^>]*href="([^"]*)"'
            content_pattern = r"<content[^>]*>(.*?)</content>"
            summary_pattern = r"<summary[^>]*>(.*?)</summary>"
            updated_pattern = r"<updated[^>]*>(.*?)</updated>"
        else:
            entry_pattern = r"<item[^>]*>(.*?)</item>"
            title_pattern = r"<title[^>]*>(.*?)</title>"
            link_pattern = r"<link[^>]*>(.*?)</link>"
            content_pattern = r"<description[^>]*>(.*?)</description>"
            summary_pattern = r"<content:encoded[^>]*>(.*?)</content:encoded>"
            updated_pattern = r"<pubDate[^>]*>(.*?)</pubDate>"

        entries = re.findall(entry_pattern, xml_text, re.DOTALL | re.IGNORECASE)[:limit]

        for entry_xml in entries:
            title_m = re.search(title_pattern, entry_xml, re.DOTALL | re.IGNORECASE)
            link_m = re.search(link_pattern, entry_xml, re.DOTALL | re.IGNORECASE)
            content_m = re.search(content_pattern, entry_xml, re.DOTALL | re.IGNORECASE)
            summary_m = re.search(summary_pattern, entry_xml, re.DOTALL | re.IGNORECASE)
            pub_m = re.search(updated_pattern, entry_xml, re.DOTALL | re.IGNORECASE)

            title = self._clean_xml(title_m.group(1)) if title_m else "Untitled"
            content = self._clean_xml((content_m or summary_m).group(1)) if (content_m or summary_m) else ""
            url = link_m.group(1).strip() if link_m else ""
            published = pub_m.group(1).strip() if pub_m else ""

            if title or content:
                items.append(
                    CTIFeedItem(
                        source=self._feed_name,
                        title=title,
                        content=content or title,
                        url=url,
                        published=published,
                        tags=[self._feed_name],
                    )
                )

        return items

    @staticmethod
    def _clean_xml(text: str) -> str:
        """Strip XML/HTML tags and decode entities."""
        import re

        text = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", text, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", "", text)
        text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
        return text.strip()


# ── CISA Known Exploited Vulnerabilities Feed ────────────────────────────────


class CISAKEVConnector(CTIConnector):
    """Fetches CISA's Known Exploited Vulnerabilities catalog."""

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @property
    def name(self) -> str:
        return "cisa-kev"

    async def fetch(
        self,
        since: str = "",
        limit: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch recent KEV entries from CISA."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not installed — CISA KEV connector unavailable")
            return []

        items: list[CTIFeedItem] = []

        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(
                    self.CATALOG_URL,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp,
            ):
                if resp.status != 200:
                    logger.error("CISA KEV returned %d", resp.status)
                    return []
                data = await resp.json()

            vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []

            # Filter by date if since provided
            if since:
                vulns = [v for v in vulns if v.get("dateAdded", "") >= since]

            # Take most recent
            vulns = vulns[-limit:]

            for vuln in vulns:
                cve_id = vuln.get("cveID", "")
                vendor = vuln.get("vendorProject", "")
                product = vuln.get("product", "")
                title = f"{cve_id} — {vendor} {product}"
                description = vuln.get("shortDescription", "")
                known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

                content = (
                    f"{title}\n{description}\n"
                    f"Known Ransomware Use: {known_ransomware}\n"
                    f"Required Action: {vuln.get('requiredAction', 'N/A')}"
                )

                tags = [f"vendor:{vendor}", f"product:{product}"]
                if known_ransomware.lower() == "known":
                    tags.append("ransomware")

                items.append(
                    CTIFeedItem(
                        source="cisa-kev",
                        title=title,
                        content=content,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        published=vuln.get("dateAdded", ""),
                        tags=tags,
                        iocs=[cve_id],
                        raw=vuln,
                    )
                )

            logger.info("Fetched %d KEV entries from CISA", len(items))

        except Exception as exc:
            logger.error("CISA KEV fetch failed: %s", exc)

        return items


# ── Feed Manager ──────────────────────────────────────────────────────────────


class CTIFeedManager:
    """Manages multiple CTI feed connectors and deduplicates results.

    Usage::

        manager = CTIFeedManager(
            connectors=[
                MISPConnector("https://misp.local", api_key="..."),
                OTXConnector(api_key="..."),
                CISAKEVConnector(),
                RSSConnector("https://example.com/feed.xml", "example_blog"),
            ]
        )
        all_items = await manager.fetch_all()
    """

    def __init__(
        self,
        connectors: list[CTIConnector] | None = None,
        dedup_window_hours: int = 24,
    ) -> None:
        self._connectors: list[CTIConnector] = connectors or []
        self._seen_ids: set[str] = set()
        self._dedup_window_hours = dedup_window_hours
        self._last_fetch: dict[str, float] = {}

    def add_connector(self, connector: CTIConnector) -> None:
        """Add a feed connector."""
        self._connectors.append(connector)

    @property
    def connectors(self) -> list[CTIConnector]:
        return list(self._connectors)

    async def fetch_all(
        self,
        since: str = "",
        limit_per_feed: int = 50,
    ) -> list[CTIFeedItem]:
        """Fetch from all connectors in parallel, deduplicate, and return."""
        if not self._connectors:
            logger.warning("No CTI connectors configured")
            return []

        # Fetch from all connectors concurrently
        tasks = [connector.fetch(since=since, limit=limit_per_feed) for connector in self._connectors]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten and deduplicate
        all_items: list[CTIFeedItem] = []
        new_items: list[CTIFeedItem] = []

        for result in results:
            if isinstance(result, Exception):
                logger.error("Connector failed: %s", result)
                continue
            all_items.extend(result)

        for item in all_items:
            if item.doc_id not in self._seen_ids:
                self._seen_ids.add(item.doc_id)
                new_items.append(item)

        # Sort by published date
        new_items.sort(key=lambda x: x.published or "", reverse=True)

        logger.info(
            "CTI feeds: %d total, %d new (across %d connectors)",
            len(all_items),
            len(new_items),
            len(self._connectors),
        )

        return new_items

    def get_stats(self) -> dict[str, Any]:
        """Get feed statistics."""
        connector_stats: dict[str, dict[str, Any]] = {}
        for conn in self._connectors:
            last = self._last_fetch.get(conn.name, 0)
            connector_stats[conn.name] = {
                "last_fetch": datetime.fromtimestamp(last, tz=timezone.utc).isoformat() if last else "never",
            }

        return {
            "connector_count": len(self._connectors),
            "connectors": connector_stats,
            "total_seen_ids": len(self._seen_ids),
            "dedup_window_hours": self._dedup_window_hours,
        }

    def clear_dedup_cache(self) -> None:
        """Reset the dedup cache."""
        self._seen_ids.clear()
        self._last_fetch.clear()
