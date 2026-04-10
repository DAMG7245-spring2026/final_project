"""
CISA Advisory Scraper
Scrapes Analysis Reports and Cybersecurity Advisories from CISA,
uploads raw HTML to S3, and records metadata in Snowflake advisories table.
"""
import logging
import random
import time
from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional
from urllib.parse import urlparse

import boto3
import requests
import snowflake.connector
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

from app.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories"

ADVISORY_TYPES = {
    "analysis_report": 65,
    "cybersecurity_advisory": 94,
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

START_YEAR = 2018
MAX_RETRIES = 3
DELAY_MIN = 2.0  # seconds
DELAY_MAX = 5.0  # seconds


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class AdvisoryMeta:
    advisory_id: str
    title: str
    url: str
    published_date: date
    advisory_type: str


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, params: dict = None) -> Optional[requests.Response]:
    """GET with retry logic and random delay."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
            if resp.status_code == 200:
                return resp
            logger.warning(f"HTTP {resp.status_code} on attempt {attempt}: {url}")
        except requests.RequestException as e:
            logger.warning(f"Request error on attempt {attempt}: {e}")

        if attempt < MAX_RETRIES:
            time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    logger.error(f"Failed after {MAX_RETRIES} attempts: {url}")
    return None


def _sleep():
    time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))


# ---------------------------------------------------------------------------
# List page parsing
# ---------------------------------------------------------------------------

def _parse_advisory_id(url: str) -> Optional[str]:
    """Extract advisory_id from URL path, e.g. 'aa25-343a' from the last segment."""
    path = urlparse(url).path.rstrip("/")
    return path.split("/")[-1] if path else None


def _parse_list_page(html: str) -> list[AdvisoryMeta]:
    """Parse one page of the advisories list, return AdvisoryMeta items."""
    soup = BeautifulSoup(html, "html.parser")
    results = []

    for article in soup.select("article.c-teaser"):
        # Date
        time_tag = article.select_one("time[datetime]")
        if not time_tag:
            continue
        published_date = datetime.fromisoformat(
            time_tag["datetime"].replace("Z", "+00:00")
        ).date()

        # Advisory type label
        meta_tag = article.select_one(".c-teaser__meta")
        advisory_type_label = meta_tag.get_text(strip=True).lower() if meta_tag else ""
        if "analysis report" in advisory_type_label:
            advisory_type = "analysis_report"
        elif "cybersecurity advisory" in advisory_type_label:
            advisory_type = "cybersecurity_advisory"
        else:
            continue  # skip other types that may appear

        # Title and URL
        link_tag = article.select_one("h3.c-teaser__title a")
        if not link_tag:
            continue
        title = link_tag.get_text(strip=True)
        raw_url = link_tag["href"]

        # Normalise URL (strip wayback machine prefix if present)
        if "cisa.gov" in raw_url:
            idx = raw_url.find("https://www.cisa.gov")
            if idx > 0:
                raw_url = raw_url[idx:]
        elif raw_url.startswith("/"):
            raw_url = "https://www.cisa.gov" + raw_url

        advisory_id = _parse_advisory_id(raw_url)
        if not advisory_id:
            continue

        results.append(AdvisoryMeta(
            advisory_id=advisory_id,
            title=title,
            url=raw_url,
            published_date=published_date,
            advisory_type=advisory_type,
        ))

    return results


# ---------------------------------------------------------------------------
# Snowflake helpers
# ---------------------------------------------------------------------------

def _get_snowflake_conn():
    s = get_settings()
    return snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )


def _get_existing_ids(conn) -> set[str]:
    """Return the set of advisory_ids already in Snowflake."""
    cur = conn.cursor()
    cur.execute("SELECT advisory_id FROM advisories")
    ids = {row[0] for row in cur.fetchall()}
    cur.close()
    return ids


def _insert_advisory(conn, meta: AdvisoryMeta, s3_path: str):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO advisories
            (advisory_id, title, url, s3_raw_path, published_date, advisory_type)
        SELECT %(advisory_id)s, %(title)s, %(url)s, %(s3_raw_path)s,
               %(published_date)s::DATE, %(advisory_type)s
        WHERE NOT EXISTS (
            SELECT 1 FROM advisories WHERE advisory_id = %(advisory_id)s
        )
        """,
        {
            "advisory_id": meta.advisory_id,
            "title": meta.title,
            "url": meta.url,
            "s3_raw_path": s3_path,
            "published_date": meta.published_date.isoformat(),
            "advisory_type": meta.advisory_type,
        },
    )
    conn.commit()
    cur.close()


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------

def _upload_to_s3(html: str, advisory_id: str) -> str:
    """Upload raw HTML to S3, return the S3 key."""
    s = get_settings()
    s3 = boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id,
        aws_secret_access_key=s.aws_secret_access_key,
        region_name=s.aws_region,
    )
    key = f"raw/advisories/{advisory_id}.html"
    s3.put_object(
        Bucket=s.s3_bucket,
        Key=key,
        Body=html.encode("utf-8"),
        ContentType="text/html",
    )
    return key


# ---------------------------------------------------------------------------
# Main scrape function
# ---------------------------------------------------------------------------

def scrape_advisories(
    advisory_types: list[str] = None,
    start_year: int = START_YEAR,
    dry_run: bool = False,
) -> list[AdvisoryMeta]:
    """
    Scrape CISA advisories and store them in S3 + Snowflake.

    Args:
        advisory_types: list of type keys to scrape, e.g.
                        ["analysis_report", "cybersecurity_advisory"].
                        Defaults to both.
        start_year:     Stop paginating when advisory date < Jan 1 of this year.
        dry_run:        If True, only collect metadata without uploading or inserting.

    Returns:
        List of AdvisoryMeta for every new advisory processed.
    """
    if advisory_types is None:
        advisory_types = list(ADVISORY_TYPES.keys())

    conn = None if dry_run else _get_snowflake_conn()
    existing_ids = _get_existing_ids(conn) if conn else set()
    cutoff = date(start_year, 1, 1)

    all_new: list[AdvisoryMeta] = []

    for advisory_type in advisory_types:
        type_id = ADVISORY_TYPES[advisory_type]
        logger.info(f"Scraping type={advisory_type} (id={type_id}) from {start_year} onwards")
        page = 0

        while True:
            params = {"f[0]": f"advisory_type:{type_id}", "page": page}
            resp = _get(BASE_URL, params=params)
            if resp is None:
                logger.error(f"Giving up on page {page} for {advisory_type}")
                break

            items = _parse_list_page(resp.text)
            if not items:
                logger.info(f"No items on page {page}, stopping")
                break

            stop = False
            for meta in items:
                if meta.published_date < cutoff:
                    logger.info(f"Reached cutoff date ({meta.published_date}), stopping")
                    stop = True
                    break

                if meta.advisory_id in existing_ids:
                    logger.debug(f"Skip existing: {meta.advisory_id}")
                    continue

                logger.info(f"New advisory: {meta.advisory_id} ({meta.published_date})")

                if not dry_run:
                    # Download HTML
                    html_resp = _get(meta.url)
                    if html_resp is None:
                        logger.warning(f"Could not download {meta.url}, skipping")
                        continue

                    # Upload to S3
                    s3_key = _upload_to_s3(html_resp.text, meta.advisory_id)

                    # Insert into Snowflake
                    _insert_advisory(conn, meta, s3_key)
                    existing_ids.add(meta.advisory_id)
                    _sleep()

                all_new.append(meta)

            if stop:
                break

            page += 1
            _sleep()

    if conn:
        conn.close()

    logger.info(f"Done. Total new advisories: {len(all_new)}")
    return all_new


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    results = scrape_advisories()
    print(f"\nTotal scraped: {len(results)}")
