"""
company.py — everything about building a picture of the organization
behind a scanned domain: social presence (homepage scrape), the public
company record (Wikidata, name-validated against the domain), employee
enumeration (CrossLinked), and breach/leak exposure for both the domain's
hosts (LeakIX) and its harvested emails (XposedOrNot).

Deliberately kept separate from the rest of the tool modules — this is
the one category of "OSINT source" that's about the *organization*
rather than its infrastructure, and it's the part of the app most likely
to keep growing (more people-search sources, more breach sources) without
needing to touch anything else.
"""

import asyncio
import csv
import hashlib
import json
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

from core import (
    BASE_DIR,
    TOOL_PROFILES,
    add_emails,
    apply_variant,
    check_dns_now,
    filter_emails_to_domain,
    get_db,
    get_tool_profile,
    http_get_json,
    http_get_text,
    log_line,
    run_stream,
    store_intel,
)


async def xposedornot_lookup(scan_id: int, emails: list[str]):
    """XposedOrNot — genuinely free, no key, no account, for exactly the
    check this app's own harvested emails call for: has this specific
    address shown up in a known breach. Confirmed exact endpoint and
    response schema directly from XposedOrNot's own API docs.

    Free tier is rate-limited per IP: 2/sec, 25/hour, 100/day for the
    check-email endpoint specifically. Capped here at a modest number of
    emails per scan and throttled between requests — a domain that
    harvests dozens of emails in one scan could otherwise burn through a
    meaningful chunk of the daily quota in a single run.
    """
    if not emails:
        return
    MAX_CHECKED = 20
    checked = sorted(emails)[:MAX_CHECKED]
    if len(emails) > MAX_CHECKED:
        await log_line(
            scan_id,
            f"[xposedornot] {len(emails)} emails harvested — checking the first {MAX_CHECKED} to stay "
            f"within the free tier's daily quota (100 checks/day, shared across all scans today)",
            "meta",
        )
    await log_line(scan_id, f"[+] XposedOrNot breach check for {len(checked)} email(s)", "meta")
    for i, email in enumerate(checked):
        url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(email)}"
        try:
            data = await http_get_json(url, timeout=15)
            # "breaches" comes back as a list containing one list of
            # breach names, e.g. [["Tesco", "KiwiFarms", ...]] — flattened
            # defensively here in case a future response ever returns a
            # flat list instead.
            raw_breaches = data.get("breaches") or []
            breach_names = []
            for item in raw_breaches:
                if isinstance(item, list):
                    breach_names.extend(str(b) for b in item)
                elif item:
                    breach_names.append(str(item))
            if breach_names:
                conn = get_db()
                conn.execute(
                    "INSERT INTO leaks (scan_id, host, source, leak_type, detail) VALUES (?, ?, 'xposedornot', ?, ?)",
                    (scan_id, email, "email_breach", f"Found in {len(breach_names)} breach(es): {', '.join(breach_names[:15])}"),
                )
                conn.commit()
                conn.close()
                await log_line(scan_id, f"[xposedornot] {email}: found in {len(breach_names)} breach(es)", "out")
            else:
                await log_line(scan_id, f"[xposedornot] {email}: not found in any known breach", "out")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                await log_line(scan_id, f"[xposedornot] {email}: not found in any known breach", "out")
            elif e.code == 429:
                await log_line(
                    scan_id,
                    f"[xposedornot] rate limit hit — stopping email checks for this scan "
                    f"({i}/{len(checked)} checked before the limit)",
                    "warn",
                )
                break
            else:
                await log_line(scan_id, f"[xposedornot] {email}: HTTP {e.code}", "warn")
        except Exception as e:
            await log_line(scan_id, f"[xposedornot] {email}: failed — {e}", "warn")
        if i < len(checked) - 1:
            await asyncio.sleep(0.6)


SOCIAL_PATTERNS = {
    "twitter": r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[A-Za-z0-9_]{1,15}",
    "linkedin": r"https?://(?:www\.)?linkedin\.com/company/[A-Za-z0-9\-_%]+",
    "facebook": r"https?://(?:www\.)?facebook\.com/[A-Za-z0-9_.\-]+",
    "instagram": r"https?://(?:www\.)?instagram\.com/[A-Za-z0-9_.]+",
    "github": r"https?://(?:www\.)?github\.com/[A-Za-z0-9\-]+",
    "youtube": r"https?://(?:www\.)?youtube\.com/(?:channel|c|user|@)[A-Za-z0-9_\-]+",
}

# Anchor-text patterns for discovering a site's own About/Pricing/
# Privacy/Terms/Contact pages via its homepage navigation — matching
# how a human analyst would actually read a company's public site
# (following its own links), not guessing at content.
PAGE_CATEGORY_LINK_PATTERNS = {
    "about": [r"about\s*us", r"about", r"who\s+we\s+are", r"our\s+story"],
    "pricing": [r"pricing", r"plans\s*(?:&|and)?\s*pricing", r"plans"],
    "privacy": [r"privacy\s+(?:policy|notice)", r"privacy"],
    "terms": [r"terms\s+(?:of\s+service|and\s+conditions|&\s+conditions|of\s+use)", r"terms"],
    "contact": [r"contact\s*us", r"contact", r"get\s+in\s+touch"],
    "team": [r"meet\s+the\s+team", r"our\s+team", r"leadership", r"our\s+people", r"team", r"staff"],
}

# Fallback common path guesses, tried in order, for any category the
# homepage's own navigation links didn't resolve.
PAGE_CATEGORY_PATH_GUESSES = {
    # /za/ variants included specifically given this app's own South
    # African context — confirmed directly against a real multinational
    # target (Orange Cyberdefense) that this is a common pattern: the
    # bare domain is a country-selector page with no country-specific
    # content at all, and the actually-relevant local content (company
    # description, local contact details, local phone/address) lives
    # behind a /za/ prefix instead. Only added for about/contact/team,
    # not every category — pricing/privacy/terms are more often global/
    # shared across a multinational's country sites, so guessing a /za/
    # variant there is less likely to pay for the extra request.
    "about": ["/about", "/about-us", "/za", "/za/about-us"],
    "pricing": ["/pricing", "/plans"],
    "privacy": ["/privacy", "/privacy-policy", "/privacy-notice"],
    "terms": ["/terms", "/terms-of-service", "/terms-and-conditions", "/tos"],
    "contact": ["/contact", "/contact-us", "/za/contact"],
    "team": ["/team", "/our-team", "/about/team", "/leadership", "/staff", "/people"],
}

# Compliance/regulatory framework mentions worth surfacing when found in
# a Privacy Notice or Terms page — a direct textual mention is a real,
# citable observation (the company states this framework applies to
# them), not an inference about their actual compliance posture.
COMPLIANCE_KEYWORDS = [
    "GDPR", "CCPA", "CPRA", "HIPAA", "POPIA", "PCI-DSS", "PCI DSS",
    "SOC 2", "SOC2", "ISO 27001", "ISO27001", "PIPEDA", "LGPD", "COPPA",
]


def extract_page_links(html: str, origin: str) -> dict[str, str]:
    """Maps category -> best-matching same-origin URL found among the
    page's own <a> links, keyed by visible anchor text. At most one URL
    per category — the first link whose text matches."""
    results: dict[str, str] = {}
    try:
        origin_host = urllib.parse.urlsplit(origin).hostname or ""
    except Exception:
        return results
    for m in re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL):
        href, anchor_html = m.group(1), m.group(2)
        anchor_text = re.sub(r"<[^>]+>", " ", anchor_html).strip().lower()
        if not anchor_text or len(anchor_text) > 60:
            continue
        for category, patterns in PAGE_CATEGORY_LINK_PATTERNS.items():
            if category in results:
                continue
            if any(re.search(p, anchor_text, re.IGNORECASE) for p in patterns):
                try:
                    resolved = urllib.parse.urljoin(origin + "/", href)
                    resolved_host = urllib.parse.urlsplit(resolved).hostname or ""
                except Exception:
                    continue
                if resolved_host == origin_host:
                    results[category] = resolved
    return results


def extract_compliance_mentions(text: str) -> list[str]:
    """Case-insensitive keyword search, de-duplicating near-identical
    forms (SOC 2 / SOC2, ISO 27001 / ISO27001) to one label each."""
    found = []
    for kw in COMPLIANCE_KEYWORDS:
        if re.search(re.escape(kw), text, re.IGNORECASE):
            found.append(kw)
    normalized, seen = [], set()
    for kw in found:
        key = re.sub(r"[\s\-]", "", kw).upper()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(kw)
    return normalized


# ---------------------------------------------------------------------------
# Contact scraping — emails, phone numbers, and possible staff names from
# the company's own pages (not third-party sources like theHarvester/
# CrossLinked, which search external indexes rather than reading the
# site itself). Runs against every page social_scan already fetches, so
# no extra HTTP requests are needed for this.
# ---------------------------------------------------------------------------

# Deliberately excludes common false-positive sources: image srcset
# artifacts (photo@2x.png matches a naive email pattern), platform/
# tracking-script domains that show up in almost every site's HTML
# without being a real contact address, and obvious placeholders.
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9.+_-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
EMAIL_FALSE_POSITIVE_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "woff", "woff2", "ttf",
}
EMAIL_FALSE_POSITIVE_DOMAINS = {
    "example.com", "example.org", "domain.com", "yourdomain.com", "yourcompany.com",
    "sentry.io", "schema.org", "w3.org", "wixpress.com", "godaddy.com", "namecheap.com",
    "cloudflare.com", "google.com", "gstatic.com", "googleapis.com",
}


def extract_emails_from_html(html: str) -> tuple[set[str], set[str]]:
    """mailto: links are deliberately-published contact addresses — high
    confidence. Free-text matches in the page body catch addresses
    written out without a mailto: link, at the cost of being somewhat
    noisier, which the filters above are aimed at.

    Also returns the set of domains those mailto: links point to,
    separately from the emails themselves. Confirmed directly as a real,
    distinct gap from the redirect-target case already handled
    elsewhere: a site can stay live on its original domain with no HTTP
    redirect at all, while its own contact form/footer names a
    different domain as "where we live now" (a company that rebranded
    but kept the old domain up as a landing page, say). The mailto:
    domain is a deliberate, structural signal — someone explicitly
    coded that link into the page — so it's trustworthy evidence of
    which domain's emails are real even when nothing else on the page
    (no redirect, no canonical tag) says so.
    """
    emails = set()
    mailto_domains = set()
    for m in re.finditer(r'mailto:([a-zA-Z0-9.+_-]+@[a-zA-Z0-9.-]+)', html, re.IGNORECASE):
        email = m.group(1).lower()
        emails.add(email)
        mailto_domains.add(email.rsplit("@", 1)[1])
    text = re.sub(r"<[^>]+>", " ", html)
    for m in EMAIL_REGEX.finditer(text):
        candidate = m.group(0).lower()
        domain_part = candidate.split("@", 1)[1]
        tld = domain_part.rsplit(".", 1)[-1]
        if tld in EMAIL_FALSE_POSITIVE_TLDS or any(
            domain_part == d or domain_part.endswith("." + d) for d in EMAIL_FALSE_POSITIVE_DOMAINS
        ):
            continue
        emails.add(candidate)
    return emails, mailto_domains


# Loose on purpose — international phone formats vary too much for a
# strict pattern to be worth it, and a missed number here just means one
# fewer data point, not a false claim. tel: links (checked separately,
# below) are the high-confidence source; this free-text pattern is the
# lower-confidence supplement, same relationship as mailto: vs free-text
# email matching above.
PHONE_REGEX = re.compile(r"(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?")


def extract_phones_from_html(html: str) -> set[str]:
    phones = set()
    for m in re.finditer(r'tel:([+\d][\d\s().-]{5,})', html, re.IGNORECASE):
        cleaned = m.group(1).strip()
        if cleaned:
            phones.add(cleaned)
    text = re.sub(r"<[^>]+>", " ", html)
    for m in PHONE_REGEX.finditer(text):
        candidate = m.group(0).strip()
        digit_count = sum(c.isdigit() for c in candidate)
        if 7 <= digit_count <= 15:
            phones.add(candidate)
    return phones


# Names have no reliable textual pattern the way emails/phone numbers
# do, so this is a genuinely loose, best-effort heuristic — the same
# honest framing as the shadow-IT naming-pattern detector elsewhere in
# this app: a false positive here just means an extra name to glance
# past, a missed one means nothing claimed either way. Looks for a
# capitalized 2-4 word sequence (a plausible human name shape) within
# ~60 characters of a common job-title word, in either order ("Jane
# Smith, CEO" and "CEO Jane Smith" both match).
STAFF_TITLE_KEYWORDS = [
    "CEO", "Chief Executive Officer", "CTO", "Chief Technology Officer",
    "CFO", "Chief Financial Officer", "COO", "Chief Operating Officer",
    "CISO", "Chief Information Security Officer", "Founder", "Co-Founder",
    "President", "Director", "Manager", "Head of", "VP", "Vice President",
    "Lead", "Engineer", "Consultant", "Analyst", "Specialist", "Partner",
    "Principal", "Chairman", "Chairwoman",
]
_STAFF_NAME_PATTERN = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b")
_STAFF_TITLE_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in STAFF_TITLE_KEYWORDS) + r")\b", re.IGNORECASE
)


def extract_possible_staff_names(html: str) -> list[str]:
    # Splitting on container-level tags only (div/li/article/section/tr)
    # — not on h1-6/p/td too, which was tried first and confirmed wrong:
    # it split a name in its own <h3> away from the <p> right after it
    # holding that same person's title, even though both live inside one
    # team-member <div>. Splitting one level up keeps a single person's
    # whole card together while still separating it from the next card.
    blocks = re.split(r"</?(?:div|li|article|section|tr)[^>]*>", html, flags=re.IGNORECASE)
    title_words_lower = {t.lower() for t in STAFF_TITLE_KEYWORDS}
    found = []
    seen = set()
    for block in blocks:
        # A period at heading/paragraph boundaries, inserted before the
        # generic tag-strip below, stops the name pattern's \s+ word
        # joiner from bridging across what was originally a separate
        # element — confirmed directly as needed: without this, a
        # heading like "Director of Engineering" immediately followed
        # by a paragraph starting "Bob Jones..." reads as one
        # contiguous capitalized run, "Engineering Bob Jones", even
        # though the two came from different tags entirely.
        block = re.sub(r"</(?:h[1-6]|p)\s*>|<br\s*/?>", ". ", block, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", block)
        text = re.sub(r"\s+", " ", text).strip()
        if not _STAFF_TITLE_PATTERN.search(text):
            continue
        for name_match in _STAFF_NAME_PATTERN.finditer(text):
            name = name_match.group(1).strip()
            words = name.split()
            # Catches both a single word that's itself a title ("Bob
            # Director") and the whole candidate matching a multi-word
            # title exactly ("Chief Executive Officer" is 3 capitalized
            # words, exactly the shape this pattern looks for, and
            # would otherwise show up in the results as if it were
            # someone's actual name).
            if len(words) > 4 or any(w.lower() in title_words_lower for w in words) or name.lower() in title_words_lower:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(name)
    return found


def extract_body_text_excerpt(html: str) -> Optional[str]:
    """Fallback for when a page has no <meta name="description"> at all
    — confirmed directly as a real gap against a live target: a country-
    specific landing page can hold its actual "about this company"
    content as plain paragraph text on the page itself, with no meta
    description tag anywhere, which left company_lookup's own from-own-
    site writeup fallback (which reads exactly this field) with nothing
    to use even once the page itself was successfully found.

    Same block-splitting approach as extract_possible_staff_names above,
    for the same reason — it keeps nav/menu link text (lots of very
    short blocks) separate from genuine prose (a real paragraph-length
    block), so a country-selector's list of 190 country names doesn't
    win out over the one paragraph that's actually a description.
    """
    blocks = re.split(r"</?(?:div|li|article|section|nav|footer|header)[^>]*>", html, flags=re.IGNORECASE)
    for block in blocks:
        text = re.sub(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", " ", block, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        # A genuine description paragraph reads as prose — several
        # words, not just one short phrase repeated (a nav block full
        # of one-or-two-word links collapses to short "words" on
        # average even after joining, since there's no real sentence
        # structure holding it together) — and confirmed directly as a
        # necessary second check: a long enough list of short items
        # (a country selector with 50+ names, say) can still clear the
        # length/word-count bar on volume alone. Requiring at least one
        # sentence-ending period is what actually distinguishes prose
        # from a list — a real description has one, a list of link text
        # generally doesn't.
        word_count = len(text.split())
        has_sentence_punctuation = ". " in text or text.endswith(".")
        if len(text) >= 80 and word_count >= 12 and has_sentence_punctuation:
            return text[:400]
    return None


async def social_scan(scan_id: int, domain: str, http_assets: list[dict], tld_variants: Optional[list[str]] = None):
    """Scrapes the live homepage for social profile links and basic
    company signals (title, meta description, og:site_name, canonical/
    og:url), then discovers and reads the site's own About, Pricing,
    Privacy, Terms, and Contact pages — found via the homepage's actual
    navigation links where possible, common path guesses otherwise.
    Each discovered page's title/description gets stored; Privacy/Terms
    pages are additionally checked for named compliance framework
    mentions (GDPR, POPIA, HIPAA, etc.) — a real, citable textual
    observation, not an inference about actual compliance posture.
    Capped at one page per category to keep the request count
    reasonable.

    tld_variants, if given (other TLDs of the same base name that are
    already confirmed to resolve — e.g. sensepost.co.za alongside
    sensepost.com), are scraped too: their homepage for contacts/social
    links, and — only if the primary domain's own About page turned up
    no description — their About page as well. This is deliberately
    bounded (homepage + one About-page guess per variant, not a full
    5-category sweep) since the primary domain already gets the full
    treatment above and each variant is a secondary, lower-priority
    source, not a second scan target in its own right."""
    target = None
    for a in http_assets:
        if a.get("subdomain") == domain and a.get("status_code"):
            target = a
            break
    if not target:
        for a in http_assets:
            if a.get("status_code"):
                target = a
                break
    if not target or not target.get("url"):
        await log_line(scan_id, "[social] no live homepage to scan", "warn")
        return

    base_url = target["url"]
    parsed = urllib.parse.urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    conn = get_db()
    found: dict[str, str] = {}
    title = description = site_name = canonical = og_url = None
    pages_fetched = 0
    all_emails: set[str] = set()
    all_mailto_domains: set[str] = set()
    all_phones: set[str] = set()
    all_staff_names: list[str] = []
    seen_staff_names: set[str] = set()

    def _collect_contacts(html: str):
        # Shared by the homepage and every discovered sub-page below —
        # a footer with a general contact email/phone is common on the
        # homepage itself, not just a dedicated Contact page, so this
        # runs against all of them, not just the ones under "contact".
        emails, mailto_domains = extract_emails_from_html(html)
        all_emails.update(emails)
        all_mailto_domains.update(mailto_domains)
        all_phones.update(extract_phones_from_html(html))
        for name in extract_possible_staff_names(html):
            key = name.lower()
            if key not in seen_staff_names:
                seen_staff_names.add(key)
                all_staff_names.append(name)

    await log_line(scan_id, f"$ fetching {base_url} for social/company signals", "cmd")
    try:
        homepage_html = await http_get_text(base_url)
        pages_fetched += 1
    except Exception as e:
        homepage_html = ""
        await log_line(scan_id, f"[social] {base_url} fetch failed: {e}", "warn")

    if homepage_html:
        _collect_contacts(homepage_html)
        for platform, pat in SOCIAL_PATTERNS.items():
            m = re.search(pat, homepage_html, re.IGNORECASE)
            if m:
                found[platform] = m.group(0)

        title_m = re.search(r"<title[^>]*>([^<]{1,200})</title>", homepage_html, re.IGNORECASE)
        if title_m:
            title = title_m.group(1).strip()
        desc_m = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,300})["\']', homepage_html, re.IGNORECASE
        )
        if desc_m:
            description = desc_m.group(1).strip()
        site_m = re.search(
            r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']{1,150})["\']',
            homepage_html, re.IGNORECASE,
        )
        if site_m:
            site_name = site_m.group(1).strip()
        # Extra "what's the real main domain" signals: a canonical
        # link or og:url pointing somewhere other than this host is a
        # real, page-declared statement of the preferred URL — not a
        # guess, just reading what the page itself says.
        canon_m = re.search(
            r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', homepage_html, re.IGNORECASE
        )
        if canon_m:
            canonical = canon_m.group(1).strip()
        ogurl_m = re.search(
            r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']', homepage_html, re.IGNORECASE
        )
        if ogurl_m:
            og_url = ogurl_m.group(1).strip()

    # Discover About/Pricing/Privacy/Terms/Contact — from the homepage's
    # own navigation links first (extract_page_links), falling back to
    # common path guesses, tried in order, for any category the link
    # crawl didn't resolve.
    category_urls: dict[str, list[str]] = {}
    linked = extract_page_links(homepage_html, origin) if homepage_html else {}
    for category in PAGE_CATEGORY_PATH_GUESSES:
        if category in linked:
            category_urls[category] = [linked[category]]
        else:
            category_urls[category] = [origin.rstrip("/") + p for p in PAGE_CATEGORY_PATH_GUESSES[category]]

    pages_read = []
    page_data: list[tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []  # (category, url, title, desc, compliance_csv)
    for category, candidates in category_urls.items():
        for url in candidates:
            if url == base_url:
                break
            await asyncio.sleep(0.2)
            await log_line(scan_id, f"$ fetching {url} ({category} page)", "cmd")
            try:
                page_html = await http_get_text(url)
                pages_fetched += 1
            except Exception:
                continue  # a guessed path 404ing is expected, not worth a warning — try the next guess

            page_title_m = re.search(r"<title[^>]*>([^<]{1,200})</title>", page_html, re.IGNORECASE)
            page_title = page_title_m.group(1).strip() if page_title_m else None
            page_desc_m = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,300})["\']', page_html, re.IGNORECASE
            )
            page_desc = page_desc_m.group(1).strip() if page_desc_m else None
            # Fallback specifically for "about" — confirmed directly as
            # a real, needed case: a country-specific landing page can
            # hold its actual company description as plain paragraph
            # text with no meta description tag anywhere. Only for
            # "about", not every category — the value of a body-text
            # excerpt is highest here, since this is what
            # company_lookup's own from-own-site writeup fallback reads.
            if category == "about" and not page_desc:
                page_desc = extract_body_text_excerpt(page_html)

            # Extraction has to run before the skip check below, not
            # after it — confirmed directly as a real bug: a genuine
            # team page can easily have real names/emails in its body
            # with no <title> or meta description at all, and the old
            # ordering here silently discarded that page entirely,
            # before contact extraction ever got a chance to run on it.
            emails_before, phones_before, names_before = len(all_emails), len(all_phones), len(all_staff_names)
            _collect_contacts(page_html)
            found_contacts = (
                len(all_emails) > emails_before or len(all_phones) > phones_before or len(all_staff_names) > names_before
            )

            if not page_title and not page_desc and not found_contacts:
                continue  # nothing usable here at all — likely a soft-404 that still returned 200; try the next guess

            compliance_csv = None
            if category in ("privacy", "terms"):
                page_text = re.sub(r"<[^>]+>", " ", page_html)
                mentions = extract_compliance_mentions(page_text)
                if mentions:
                    compliance_csv = ", ".join(mentions)

            # Collected here, not written immediately — this loop is
            # still making more log_line calls on later iterations, and
            # log_line opens its own separate database connection to
            # write. Writing via THIS function's own held-open `conn`
            # partway through (an uncommitted transaction) blocked that
            # separate connection's write and hung the whole scan step
            # — confirmed directly by reproducing it, not assumed. All
            # writes happen in one batch after the loop instead, the
            # same way the rest of this function already handles its
            # other writes.
            page_data.append((category, url, page_title, page_desc, compliance_csv))
            pages_read.append(category)
            break  # found a usable page for this category, stop trying further guesses

    # TLD variants of this same domain (sensepost.co.za alongside
    # sensepost.com) — if any were given, their homepage can carry its
    # own footer contact details, social links, or staff names distinct
    # from the primary domain's. Scraped with its own https/http
    # fallback since discover_tld_variants only confirms DNS resolution,
    # not which scheme (if any) actually serves a page.
    variant_emails_before = len(all_emails)
    variant_hosts: set[str] = set()
    have_about_desc = any(desc for cat, _, _, desc, _ in page_data if cat == "about")
    if tld_variants:
        for variant in tld_variants:
            variant_html = ""
            variant_base = None
            for scheme in ("https://", "http://"):
                try:
                    variant_html = await http_get_text(f"{scheme}{variant}")
                    variant_base = f"{scheme}{variant}"
                    pages_fetched += 1
                    break
                except Exception:
                    continue
            if not variant_html:
                await log_line(scan_id, f"[social] {variant} (TLD variant) didn't respond on https or http — skipped", "warn")
                continue
            variant_hosts.add(variant)
            _collect_contacts(variant_html)
            # Only chase the About page too if the primary domain's own
            # About page gave us nothing — this is a targeted fallback
            # for company-description enrichment, not a second full
            # crawl per variant.
            if not have_about_desc:
                for about_path in PAGE_CATEGORY_PATH_GUESSES.get("about", []):
                    about_url = variant_base.rstrip("/") + about_path
                    await asyncio.sleep(0.2)
                    try:
                        about_html = await http_get_text(about_url)
                        pages_fetched += 1
                    except Exception:
                        continue
                    about_desc_m = re.search(
                        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,300})["\']',
                        about_html, re.IGNORECASE,
                    )
                    about_desc = about_desc_m.group(1).strip() if about_desc_m else None
                    if not about_desc:
                        about_desc = extract_body_text_excerpt(about_html)
                    _collect_contacts(about_html)
                    if about_desc:
                        page_data.append(("about", about_url, None, about_desc, None))
                        pages_read.append(f"about (via {variant})")
                        have_about_desc = True
                    break  # one guess is enough for this targeted fallback

    for category, url, page_title, page_desc, compliance_csv in page_data:
        store_intel(conn, scan_id, domain, "social", f"page:{category}:url", url)
        if page_title:
            store_intel(conn, scan_id, domain, "social", f"page:{category}:title", page_title)
        if page_desc:
            store_intel(conn, scan_id, domain, "social", f"page:{category}:description", page_desc)
        if compliance_csv:
            store_intel(conn, scan_id, domain, "social", f"page:{category}:compliance_mentions", compliance_csv)

    for platform, link in found.items():
        store_intel(conn, scan_id, domain, "social", platform, link)
    if title:
        store_intel(conn, scan_id, domain, "social", "page_title", title)
    if description:
        store_intel(conn, scan_id, domain, "social", "description", description)
    if site_name:
        store_intel(conn, scan_id, domain, "social", "site_name", site_name)
    for label, value in (("canonical_url", canonical), ("og_url", og_url)):
        if not value:
            continue
        try:
            host = (urllib.parse.urlsplit(value).hostname or "").lower()
        except Exception:
            host = ""
        if host and host != domain:
            store_intel(conn, scan_id, domain, "social", label, value)

    # origin's hostname covers an actual HTTP redirect to a different
    # domain; all_mailto_domains covers the other real case confirmed
    # directly against a live target — a site that stays up on its
    # original domain with no redirect at all, but whose own mailto:
    # links (a deliberate, structural signal, not a guess) point
    # somewhere else entirely (sensepost.com stays live, no redirect,
    # while its own contact form lists an @orangecyberdefense.com
    # address). Both are "the site's own stated domain", just
    # discovered two different ways.
    try:
        origin_host = urllib.parse.urlsplit(origin).hostname or ""
    except Exception:
        origin_host = ""
    extra_valid_domains = set(all_mailto_domains)
    if origin_host:
        extra_valid_domains.add(origin_host)
    extra_valid_domains |= variant_hosts
    kept_emails = filter_emails_to_domain(all_emails, domain, extra_domains=extra_valid_domains or None)
    # Computed here but NOT logged yet — conn still has this function's
    # own uncommitted writes open at this point, and log_line opens a
    # separate connection to write immediately. Confirmed directly as a
    # real deadlock: calling log_line here hung indefinitely, the exact
    # failure this file already warns about elsewhere for the same
    # reason. Folded into the one summary log below instead, which
    # correctly waits until after conn.commit()/conn.close().
    via_mailto_domain = kept_emails & {
        e for e in all_emails if "@" in e and e.rsplit("@", 1)[1] in all_mailto_domains
        and e.rsplit("@", 1)[1] != domain and e.rsplit("@", 1)[1] != origin_host
    }
    if kept_emails:
        add_emails(conn, scan_id, kept_emails, "social-scan")
    for i, phone in enumerate(sorted(all_phones)):
        store_intel(conn, scan_id, domain, "social", f"phone:{i}", phone)
    # Deliberately capped, same reasoning as everywhere else in this app
    # that shows a loose, best-effort signal rather than a verified
    # fact — a long tail of increasingly likely false positives isn't
    # more useful than the first several, it's just more noise to wade
    # through.
    for i, name in enumerate(all_staff_names[:25]):
        store_intel(conn, scan_id, domain, "social", f"possible_staff_name:{i}", name)

    conn.commit()
    conn.close()
    staff_name_note = (
        f"{len(all_staff_names)} possible staff name(s)" if len(all_staff_names) <= 25
        else f"25 possible staff name(s) shown (of {len(all_staff_names)} found)"
    )
    contact_summary = f"{len(kept_emails)} email(s), {len(all_phones)} phone number(s), {staff_name_note}"
    discarded_count = len(all_emails) - len(kept_emails)
    if discarded_count:
        contact_summary += f" ({discarded_count} other email(s) found but discarded — not @ this domain)"
    if via_mailto_domain:
        contact_summary += (
            f" ({len(via_mailto_domain)} of the {len(kept_emails)} kept via the site's own mailto: link "
            f"naming a different domain, not a redirect)"
        )
    if variant_hosts:
        new_from_variants = len(all_emails) - variant_emails_before
        contact_summary += (
            f" ({len(variant_hosts)} TLD variant site(s) also scanned ({', '.join(sorted(variant_hosts))})"
            + (f", contributing {new_from_variants} more email(s) before filtering" if new_from_variants else "")
            + ")"
        )
    await log_line(
        scan_id,
        f"[social] scanned {pages_fetched} page(s) — "
        f"{'profiles found: ' + ', '.join(found.keys()) if found else 'no social links found'}; "
        f"{'pages read: ' + ', '.join(pages_read) if pages_read else 'no About/Pricing/Privacy/Terms/Contact/Team pages found'}; "
        f"{contact_summary}",
        "meta",
    )


async def shodan_dns_domain(scan_id: int, domain: str, api_key: str) -> set[str]:
    url = f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={api_key}"
    await log_line(scan_id, "$ shodan dns/domain lookup", "cmd")
    names = set()
    try:
        data = await http_get_json(url)
        for prefix in data.get("subdomains", []) or []:
            host = domain if not prefix else f"{prefix}.{domain}"
            names.add(host.lower())
        await log_line(scan_id, f"[done] shodan dns lookup — {len(names)} names", "meta")
    except urllib.error.HTTPError as e:
        await log_line(scan_id, f"[error] shodan dns lookup failed: HTTP {e.code}", "error")
    except Exception as e:
        await log_line(scan_id, f"[error] shodan dns lookup failed: {e}", "error")
    return names


async def shodan_enrich_hosts(scan_id: int, ips: list[str], api_key: str):
    """Opens a fresh DB connection per IP rather than one held across the
    whole loop — if a write failed partway through an iteration, the
    connection's uncommitted transaction could linger across the next
    iteration's network wait and block other writers ('database is
    locked'). A connection scoped to each iteration can't do that: any
    failure just means that connection gets discarded, not stuck open."""
    await log_line(scan_id, f"[+] querying shodan host API for {len(ips)} unique IPs", "meta")
    for i, ip in enumerate(ips):
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            data = await http_get_json(url)
            conn = get_db()
            try:
                for field in ("org", "isp", "asn", "country_name", "os"):
                    val = data.get(field)
                    if val:
                        store_intel(conn, scan_id, ip, "shodan", field, val)
                hostnames = data.get("hostnames") or []
                if hostnames:
                    store_intel(conn, scan_id, ip, "shodan", "hostnames", ", ".join(hostnames))
                vulns = data.get("vulns")
                if vulns:
                    vulns_sorted = sorted(vulns)
                    store_intel(conn, scan_id, ip, "shodan", "vulns", ", ".join(vulns_sorted))
                    # Same fix as internetdb_lookup in app.py, same
                    # reasoning: these CVEs previously only existed as
                    # text in host_intel, invisible from the Vulnerability
                    # tab. The full Shodan API's vulns list is the same
                    # kind of signal InternetDB gives (confirmed
                    # fingerprint match, not a verified live exploit).
                    for cve in vulns_sorted:
                        conn.execute(
                            "INSERT INTO vulnerabilities (scan_id, host, source, template_id, name, severity, "
                            "matched_at, is_takeover, detail) VALUES (?, ?, 'shodan', ?, ?, 'high', ?, 0, ?)",
                            (
                                scan_id, ip, cve, f"Known vulnerable service ({cve})",
                                f"https://nvd.nist.gov/vuln/detail/{cve}",
                                "Flagged by Shodan — the service's fingerprint matches a known-vulnerable "
                                "version. This is a signature match, not a verified live exploit; confirm "
                                "manually before treating it as certain.",
                            ),
                        )
                services = 0
                for item in data.get("data", []) or []:
                    port = item.get("port")
                    if not port:
                        continue
                    product = item.get("product", "") or ""
                    version = item.get("version", "") or ""
                    svc = (product + " " + version).strip()
                    upsert_port(conn, scan_id, ip, int(port), "shodan", svc or None)
                    services += 1
                conn.commit()
            finally:
                conn.close()
            await log_line(scan_id, f"[shodan] {ip}: {services} services, org={data.get('org', '-')}", "out")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                await log_line(scan_id, f"[shodan] {ip}: no data on record", "warn")
            else:
                await log_line(scan_id, f"[shodan] {ip}: HTTP {e.code}", "warn")
        except Exception as e:
            await log_line(scan_id, f"[shodan] {ip}: failed — {e}", "warn")
        if i < len(ips) - 1:
            await asyncio.sleep(1)


# ---------------------------------------------------------------------------
# Hunter.io — verified, *found* emails (not guessed from a pattern), plus
# the domain's detected naming convention. Optional, API-key-gated: added
# specifically because CrossLinked (names, not emails, by default) and
# theHarvester (search-engine scraping, easily picks up a third-party
# ISP/MSSP's own address instead of the target company's) were both
# falling short of "actual related emails" for the target org. Free tier
# is 50 lookups/month, no card required — capped at a modest per-scan
# limit here so one domain can't burn the whole monthly quota alone.
async def hunter_lookup(scan_id: int, domain: str, api_key: str):
    limit = 25
    url = (
        f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(domain)}"
        f"&api_key={urllib.parse.quote(api_key)}&limit={limit}"
    )
    # Never log the URL itself — it carries the API key. Same rule as
    # shodan_dns_domain/shodan_enrich_hosts above: a generic description
    # only in the cmd-style log line.
    await log_line(scan_id, "$ hunter.io domain search", "cmd")
    try:
        data = await http_get_json(url)
        payload = data.get("data") or {}
        emails_found = payload.get("emails") or []
        conn = get_db()
        try:
            org = payload.get("organization")
            if org:
                store_intel(conn, scan_id, domain, "hunter", "organization", org)
            pattern = payload.get("pattern")
            if pattern:
                store_intel(conn, scan_id, domain, "hunter", "pattern", pattern)
            addrs = set()
            for e in emails_found:
                value = e.get("value")
                if not value:
                    continue
                addrs.add(value.lower())
                name = " ".join(p for p in (e.get("first_name"), e.get("last_name")) if p).strip()
                label = name or value
                detail_bits = []
                if e.get("position"):
                    detail_bits.append(e["position"])
                if e.get("confidence") is not None:
                    detail_bits.append(f"{e['confidence']}% confidence")
                detail = f"{value} — " + ", ".join(detail_bits) if detail_bits else value
                # Keyed by email (unique per row) rather than by name —
                # CrossLinked keys employee:<name> because it never has an
                # address to disambiguate with; Hunter always has one.
                store_intel(conn, scan_id, domain, "hunter", f"employee:{value}", f"{label} — {detail}" if label != value else detail)
            if addrs:
                add_emails(conn, scan_id, addrs, "hunter")
            conn.commit()
        finally:
            conn.close()
        if emails_found:
            await log_line(
                scan_id,
                f"[+] hunter.io: {len(emails_found)} email(s) found for {domain}"
                + (f", pattern={payload.get('pattern')}" if payload.get("pattern") else ""),
                "out",
            )
        else:
            await log_line(scan_id, f"[hunter] no emails found for {domain}", "warn")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            await log_line(scan_id, "[error] hunter.io lookup failed: HTTP 401 — invalid API key", "error")
        elif e.code == 403:
            await log_line(scan_id, "[error] hunter.io lookup failed: HTTP 403 — plan doesn't allow this request", "error")
        elif e.code == 429:
            await log_line(scan_id, "[error] hunter.io lookup failed: HTTP 429 — monthly lookup quota used up", "error")
        else:
            await log_line(scan_id, f"[error] hunter.io lookup failed: HTTP {e.code}", "error")
    except Exception as e:
        await log_line(scan_id, f"[error] hunter.io lookup failed: {e}", "error")


# ---------------------------------------------------------------------------
# Company data lookup (Wikidata) — free, no key, and self-verifying: a
# name search alone is unreliable (lots of companies share generic names),
# so this only accepts a candidate entity if its own "official website"
# claim actually matches the domain being scanned. If nothing confirms,
# nothing is shown — no guessed founding dates or headquarters.
# ---------------------------------------------------------------------------
def _wikidata_value(entity: dict, prop: str):
    try:
        return entity["claims"][prop][0]["mainsnak"]["datavalue"]["value"]
    except (KeyError, IndexError, TypeError):
        return None


def _wikidata_all_values(entity: dict, prop: str) -> list:
    out = []
    for claim in entity.get("claims", {}).get(prop, []):
        try:
            out.append(claim["mainsnak"]["datavalue"]["value"])
        except (KeyError, TypeError):
            continue
    return out


def _host_matches_domain(host: str, domain: str) -> bool:
    # str.lstrip(chars) strips any leading characters found in the given
    # SET, not the literal prefix — ".lstrip('www.')" was silently
    # mangling any host starting with a bare "w" that wasn't actually a
    # "www." prefix (e.g. "wikipedia.org" -> "ikipedia.org",
    # "wework.com" -> "ework.com"), a real, separate bug from the
    # User-Agent issue above. A proper literal-prefix strip is needed
    # instead.
    host = (host or "").lower()
    if host.startswith("www."):
        host = host[4:]
    domain = (domain or "").lower()
    return bool(host) and (host == domain or domain.endswith("." + host) or host.endswith("." + domain))


async def wikipedia_summary(title: str) -> Optional[dict]:
    """Intro paragraph + short description for a Wikipedia article via the
    REST summary API — no key needed. Only ever called with a title that
    came from a Wikidata entity's own sitelinks, so by the time this runs
    the company match has already been confirmed via official-website."""
    try:
        slug = urllib.parse.quote(title.replace(" ", "_"))
        return await http_get_json(f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}", timeout=10)
    except Exception:
        return None


async def duckduckgo_abstract(query: str) -> Optional[dict]:
    """Free, no-key instant-answer lookup — the fallback write-up source
    for companies that don't have a Wikidata entry. DuckDuckGo's instant
    answers are themselves usually Wikipedia-sourced, so this mostly
    covers cases where Wikidata's own search missed a valid match; it's
    still worth trying since it's free and adds coverage. Unlike the
    Wikidata path, there's no official-website field to verify against
    here, so anything found this way is stored and labeled as
    unverified — a name match, not a confirmed one."""
    try:
        url = f"https://api.duckduckgo.com/?q={urllib.parse.quote(query)}&format=json&no_html=1&skip_disambig=1"
        return await http_get_json(url, timeout=10)
    except Exception:
        return None


# Common WHOIS privacy-protection service names — matched case-insensitively
# against `registrant_org` so those never get used as a stand-in for the
# real company name (see get_company_name_candidates below).
PRIVACY_ORG_PATTERN = re.compile(
    r"privacy|proxy|whoisguard|redacted|withheld|domains by proxy|"
    r"perfect privacy|contact privacy|identity protect|private registration|"
    r"data protected|not disclosed|gdpr[\s-]?masked|privacyguardian",
    re.IGNORECASE,
)


# Generic subdomain labels that are never a brand/company name on their
# own — seeing one as a redirect target's first label (or as the scanned
# domain's own first label) is not evidence of anything, just common
# hosting/routing convention. "www" is by far the most common case (a
# bare domain redirecting to its own www subdomain), but the others are
# the same category of false signal.
NON_BRAND_SUBDOMAIN_LABELS = {"www", "web", "m", "mobile", "portal", "secure", "shop", "mail", "webmail", "app"}


def get_company_name_candidates(scan_id: int, domain: str) -> list[str]:
    """Best-guess candidate company names for tools that need one, not a
    domain (Wikidata lookup, CrossLinked) — pulled from whatever
    whois/social intel this scan has already gathered, falling back to
    the domain's own label if nothing better is available. Reads fresh
    from the DB rather than in-memory pipeline state, since whois and
    social-scan run as separate earlier stages.

    If a company name was supplied when the scan was started (the
    "Company name" field next to the domain input, for when a domain
    doesn't match the actual registered company name), that goes first —
    it's what the person actually told us, ahead of anything guessed.

    Second priority: if httpx recorded that the domain's homepage
    redirects to an entirely different domain (see the "redirects_to"
    intel written during the httpx step), that's real, verifiable
    evidence of the current brand — not a guess. A rebranded/acquired
    company (sensepost.com now serving from orangecyberdefense.com, say)
    is exactly the case a name-only guess handles badly: the old brand
    name might not even have its own Wikidata entity anymore, while the
    redirect target's domain label is a much better search term for
    whoever actually owns the site today.

    WHOIS privacy protection is extremely common now (many registrars
    default to it), so `registrant_org` is very often a privacy service's
    own name — "WhoisGuard Protected", "Domains By Proxy, LLC", "REDACTED
    FOR PRIVACY" — rather than the actual company. Using that verbatim as
    a company name for something like CrossLinked just wastes the search
    on a name that will never match real employees, so it's filtered out
    here rather than trusted at face value.
    """
    conn = get_db()
    scan_row = conn.execute("SELECT company_name FROM scans WHERE id = ?", (scan_id,)).fetchone()
    redirect_row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='httpx' AND field='redirects_to'", (scan_id,)
    ).fetchone()
    whois_row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='whois' AND field='registrant_org'", (scan_id,)
    ).fetchone()
    site_row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='social' AND field='site_name'", (scan_id,)
    ).fetchone()
    conn.close()
    candidates = []
    if scan_row and scan_row["company_name"]:
        candidates.append(scan_row["company_name"])
    if redirect_row and redirect_row["value"]:
        try:
            redirect_host = urllib.parse.urlsplit(redirect_row["value"]).hostname or ""
        except Exception:
            redirect_host = ""
        if redirect_host:
            label = redirect_host.split(".")[0]
            # Confirmed as a real, recurring bug: a bare domain 301-
            # redirecting to its own "www" subdomain is the single most
            # common redirect pattern on the web, not evidence of a
            # rebrand — but this check only ever compared the redirect
            # label against the domain's own first label, so
            # example.com -> www.example.com passed ("www" != "example")
            # and "www" got used as a company-name candidate for
            # CrossLinked/Wikidata lookups. NON_BRAND_SUBDOMAIN_LABELS
            # covers "www" and a few other generic, non-brand subdomain
            # labels that would pollute a search the same way.
            if label and label.lower() not in NON_BRAND_SUBDOMAIN_LABELS and label.lower() != domain.split(".")[0].lower():
                candidates.append(label)
    whois_org = whois_row["value"] if whois_row else None
    if whois_org and not PRIVACY_ORG_PATTERN.search(whois_org):
        candidates.append(whois_org)
    if site_row:
        candidates.append(site_row["value"])
    # Same non-brand-label guard applies to the final domain-label
    # fallback: if the scan was started on "www.example.com" directly
    # (the domain normalization at scan-start doesn't strip a leading
    # "www." label — a deliberate separate decision, not assumed safe to
    # change here), this still shouldn't hand "www" to CrossLinked/
    # Wikidata as a last resort. Falls through to the next label instead
    # (example.com's own "example"), which is always a better guess than
    # a generic subdomain label.
    domain_labels = [l for l in domain.split(".") if l.lower() not in NON_BRAND_SUBDOMAIN_LABELS]
    candidates.append((domain_labels or domain.split("."))[0])
    return candidates


def get_redirect_target_domain(scan_id: int) -> Optional[str]:
    """The hostname a scan's root domain actually redirects to, if any —
    used by company_lookup to also accept an official-website match
    against the redirect target, not just the originally-scanned domain.
    Same underlying intel as get_company_name_candidates' redirect
    candidate, exposed separately since company_lookup needs the
    hostname itself (for domain matching), not a name guess derived from
    it."""
    conn = get_db()
    row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='httpx' AND field='redirects_to'", (scan_id,)
    ).fetchone()
    conn.close()
    if not row or not row["value"]:
        return None
    try:
        return urllib.parse.urlsplit(row["value"]).hostname or None
    except Exception:
        return None


# A reasonable, extensible default — not exhaustive, deliberately kept
# short so this stays a quick existence check rather than a slow sweep.
# This is the set used by the AUTOMATIC paths (company_lookup's Wikidata
# match, and social_scan's homepage-scraping of each resolving variant)
# — unlike the manual "Check other TLDs" button below, those paths don't
# just do a DNS check, they fetch pages too, so this list stays small and
# high-confidence rather than global. .co.za/.africa included specifically
# given this app's own South African context; .app/.online added since
# both are common enough for a legitimate org's actual site, not just a
# squatted lookalike, to make the curated-not-global bar.
TLD_VARIANTS_TO_CHECK = ["com", "co.za", "net", "org", "io", "co", "africa", "biz", "app", "online"]

# The broad, global, continent-grouped set — used ONLY by the manual
# "🌐 Check other TLDs" button (discover_tld_variants_global below), which
# is explicitly user-triggered and DNS-only (no page fetching), so
# checking ~90 candidates concurrently is cheap and bounded. Grouped by
# continent so the UI can show results that way rather than one long
# undifferentiated list — not exhaustive (there are ~250 ccTLDs in
# existence), but covers the ccTLDs an actual business is realistically
# registered under per major region, plus the new gTLDs (.online, .app,
# .dev, .tech, etc.) that increasingly get used as a primary domain
# rather than a ccTLD at all.
TLD_CONTINENT_GROUPS: dict[str, list[str]] = {
    "Global": [
        "com", "net", "org", "io", "co", "biz", "info", "online", "app",
        "dev", "tech", "site", "store", "xyz", "ai", "cloud", "digital", "agency",
        # Added on request — "me"/"cc" are common alt-brand picks regardless
        # of industry; "systems"/"security"/"solutions"/"consulting"/
        # "group"/"services" skew toward exactly the kind of org this app's
        # own target list leans toward (security consultancies, MSPs,
        # professional-services firms), where a secondary or campaign
        # domain under one of these is a realistic, not hypothetical, find.
        "me", "cc", "systems", "security", "solutions", "consulting", "group", "services",
    ],
    "Africa": [
        "co.za", "africa", "co.ke", "com.ng", "co.tz", "co.ug", "co.zw",
        "com.gh", "co.mz", "com.na", "co.bw", "co.ao", "com.eg", "ma", "co.rw", "co.zm",
    ],
    "Europe": [
        "co.uk", "de", "fr", "nl", "es", "it", "eu", "ch", "se", "no",
        "dk", "pl", "pt", "ie", "be", "at", "fi", "gr", "cz", "ro",
    ],
    "Americas": [
        "us", "ca", "com.br", "com.mx", "com.ar", "com.co", "cl",
        "com.pe", "com.uy", "com.ve",
    ],
    "Asia": [
        "co.in", "com.cn", "co.jp", "com.sg", "com.hk", "co.kr", "com.my",
        "co.th", "com.vn", "com.ph", "com.pk", "com.bd", "com.tw", "co.id",
    ],
    "Middle East": [
        "com.sa", "ae", "co.il", "com.tr", "qa", "com.kw", "com.jo",
        "com.lb", "om", "com.bh",
    ],
    "Oceania": [
        "com.au", "co.nz", "com.fj", "com.pg",
    ],
}


async def discover_tld_variants_global(domain: str) -> list[dict]:
    """Broad, continent-labeled existence check across TLD_CONTINENT_GROUPS
    for the manual TLD-check button — unlike discover_tld_variants above,
    this returns EVERY candidate checked (not just the resolving ones),
    tagged with which continent/region group it belongs to, so the caller
    can report "checked N, M resolve" and the UI can group the results by
    region instead of one flat list. DNS-only, same as discover_tld_variants,
    and for the same reason — this is existence-checking, not investigation.
    """
    parts = domain.lower().split(".")
    label = parts[0] if parts and parts[0] else domain.lower()
    original_suffix = ".".join(parts[1:]) if len(parts) > 1 else None

    seen_tlds: set[str] = set()
    candidates: list[tuple[str, str]] = []  # (tld, continent)
    for continent, tlds in TLD_CONTINENT_GROUPS.items():
        for tld in tlds:
            if tld == original_suffix or tld in seen_tlds:
                continue
            seen_tlds.add(tld)
            candidates.append((tld, continent))

    full_domains = [f"{label}.{tld}" for tld, _ in candidates]
    if not full_domains:
        return []
    resolved = await asyncio.gather(*[check_dns_now(d) for d in full_domains])
    return [
        {"domain": d, "tld": tld, "continent": continent, "resolves": ok}
        for (tld, continent), d, ok in zip(candidates, full_domains, resolved)
    ]


async def discover_tld_variants(domain: str) -> list[str]:
    """Checks whether the same base name is registered under other common
    TLDs — scanning sensepost.com also checking sensepost.co.za, for
    instance. A company frequently owns (or someone else has squatted)
    the same name under multiple TLDs, and a variant that's actually
    live is either genuinely related infrastructure this app would
    otherwise never see, or a lookalike domain worth flagging — either
    way, real signal a single-domain scan misses by design.

    Lightweight existence check only (DNS resolution), not a full scan
    of each variant — this surfaces what exists, it doesn't investigate
    it. Runs all candidates concurrently since each is an independent,
    fast DNS lookup.
    """
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return []
    label = parts[0]
    original_suffix = ".".join(parts[1:])

    candidates = [f"{label}.{tld}" for tld in TLD_VARIANTS_TO_CHECK if tld != original_suffix]
    if not candidates:
        return []
    results = await asyncio.gather(*[check_dns_now(c) for c in candidates])
    return [c for c, ok in zip(candidates, results) if ok]


# The "front side" counterpart to TLD_CONTINENT_GROUPS — same idea
# (manual, DNS-only, user-triggered, grouped for the UI), just checking
# the *prefix* instead of the suffix. The normal scan pipeline already
# enumerates real subdomains properly (subfinder/amass/crt.sh/etc., fed
# by whatever certs/search engines/CT logs actually know about), so this
# isn't trying to replace that — it exists for the same reason the TLD
# button does: a quick, no-scan-required peek at a curated list of the
# prefixes a pentester would specifically think to check by hand (admin
# panels, VPN/remote-access gateways, staging environments, mail
# infrastructure) before committing to a full scan, grouped by what kind
# of exposure each category actually represents rather than one flat list.
SUBDOMAIN_PREFIX_GROUPS: dict[str, list[str]] = {
    "Admin & management": [
        "admin", "administrator", "cpanel", "whm", "panel", "manage", "portal",
        "dashboard", "console", "control", "webmin", "phpmyadmin", "pma",
    ],
    "Remote access": [
        "vpn", "remote", "citrix", "sso", "login", "auth", "owa", "exchange",
        "rdp", "rds", "gateway", "accesspoint", "anyconnect", "globalprotect",
    ],
    "Dev & staging": [
        "dev", "develop", "staging", "stage", "test", "testing", "uat", "qa",
        "demo", "sandbox", "preprod", "beta", "preview",
    ],
    "Mail & comms": [
        "mail", "webmail", "smtp", "pop", "imap", "mx", "autodiscover",
        "mail2", "email",
    ],
    "Infrastructure & API": [
        "api", "api2", "ns1", "ns2", "cdn", "proxy", "gw", "lb", "status",
        "monitor", "grafana", "kibana", "jenkins", "git", "gitlab", "ci",
        "docker", "k8s", "db", "backup", "files", "ftp", "sftp",
    ],
    "Web & customer-facing": [
        "www", "www2", "web", "m", "mobile", "app", "apps", "shop", "store",
        "blog", "news", "support", "help", "docs", "wiki", "secure", "my",
        "account", "accounts", "cloud", "static", "assets", "img", "media",
        "intranet", "extranet", "partner", "partners",
    ],
}


async def discover_subdomain_prefixes(domain: str) -> list[dict]:
    """Broad, category-labeled existence check across
    SUBDOMAIN_PREFIX_GROUPS for the manual "Check common subdomains"
    button — same shape as discover_tld_variants_global, mirrored onto
    the prefix side: returns every candidate checked (not just the
    resolving ones), tagged with which category it belongs to, so the
    UI can group results by category instead of one flat list. DNS-only
    and deliberately bounded to a curated list, same reasoning as the
    TLD check — this is existence-checking, not a brute-force sweep (the
    wordlist-driven brute-force step already in the normal scan pipeline
    covers that ground properly).
    """
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return []
    base = domain.lower()
    existing_prefix = parts[0]

    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []  # (prefix, category)
    for category, prefixes in SUBDOMAIN_PREFIX_GROUPS.items():
        for prefix in prefixes:
            if prefix == existing_prefix or prefix in seen:
                continue
            seen.add(prefix)
            candidates.append((prefix, category))

    full_hosts = [f"{prefix}.{base}" for prefix, _ in candidates]
    if not full_hosts:
        return []
    resolved = await asyncio.gather(*[check_dns_now(h) for h in full_hosts])
    return [
        {"domain": h, "prefix": prefix, "category": category, "resolves": ok}
        for (prefix, category), h, ok in zip(candidates, full_hosts, resolved)
    ]


async def _fetch_wikidata_facts(entity: dict) -> dict:
    """Extracts the structured facts + Wikipedia writeup for a single
    confirmed entity. Shared between the top-level company and, when one
    is found, its parent organization — same extraction logic either way,
    see resolve_parent_org below."""
    hq_val = _wikidata_value(entity, "P159")       # headquarters location
    country_val = _wikidata_value(entity, "P17")   # country
    industry_val = _wikidata_value(entity, "P452")  # industry
    legalform_val = _wikidata_value(entity, "P1454")  # legal form

    item_ids = [v["id"] for v in (hq_val, country_val, industry_val, legalform_val) if isinstance(v, dict) and v.get("id")]
    labels: dict[str, str] = {}
    if item_ids:
        try:
            label_data = await http_get_json(
                f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(sorted(set(item_ids)))}"
                f"&props=labels&languages=en&format=json",
                timeout=10,
            )
            for qid, ent in (label_data.get("entities") or {}).items():
                lbl = ((ent.get("labels") or {}).get("en") or {}).get("value")
                if lbl:
                    labels[qid] = lbl
        except Exception:
            pass

    def label_of(v):
        return labels.get(v["id"]) if isinstance(v, dict) and v.get("id") else None

    enwiki_title = (entity.get("sitelinks", {}).get("enwiki") or {}).get("title")
    wiki_url = f"https://en.wikipedia.org/wiki/{enwiki_title.replace(' ', '_')}" if enwiki_title else None
    extract = ""
    if enwiki_title:
        summary = await wikipedia_summary(enwiki_title)
        extract = (summary or {}).get("extract", "").strip()

    inception = _wikidata_value(entity, "P571")  # inception/founding date
    founded = None
    if isinstance(inception, dict) and inception.get("time"):
        precision = inception.get("precision", 11)
        try:
            year, month, day = inception["time"].lstrip("+").split("T")[0].split("-")
            founded = f"{year}-{month}-{day}" if precision >= 11 else (f"{year}-{month}" if precision == 10 else year)
        except Exception:
            founded = inception["time"]

    employees_val = _wikidata_value(entity, "P1128")  # employee count
    employees = None
    if isinstance(employees_val, dict) and employees_val.get("amount"):
        try:
            employees = f"{int(float(employees_val['amount'])):,}"
        except Exception:
            pass

    street_val = _wikidata_value(entity, "P6375")  # street address (rarely populated, worth trying)
    street = street_val["text"] if isinstance(street_val, dict) and street_val.get("text") else None

    return {
        "headquarters": label_of(hq_val), "country": label_of(country_val),
        "industry": label_of(industry_val), "legal_form": label_of(legalform_val),
        "founded": founded, "employees": employees, "street_address": street,
        "wiki_url": wiki_url, "extract": extract,
    }


async def resolve_parent_org(entity: dict) -> Optional[tuple[str, str, dict]]:
    """If the confirmed entity has an "owned by" (P127) or "parent
    organization" (P749) claim, fetch that parent's own facts too — one
    hop only, no further recursion up the ownership chain. This is
    precisely the "X is now part of Y, and here's what Y actually is"
    signal a single-entity lookup misses — Wikidata models corporate
    ownership well (confirmed directly against real examples before
    building this: Orange Cyberdefense's own entry states "parent
    organization or unit -> Orange"), it just was never queried before.
    Returns (parent_qid, parent_name, parent_entity) or None.
    """
    parent_val = _wikidata_value(entity, "P749") or _wikidata_value(entity, "P127")
    if not isinstance(parent_val, dict) or not parent_val.get("id"):
        return None
    parent_qid = parent_val["id"]
    try:
        parent_data = await http_get_json(f"https://www.wikidata.org/wiki/Special:EntityData/{parent_qid}.json", timeout=10)
    except Exception:
        return None
    parent_entity = (parent_data.get("entities") or {}).get(parent_qid)
    if not parent_entity:
        return None
    parent_name = ((parent_entity.get("labels") or {}).get("en") or {}).get("value") or parent_qid
    return parent_qid, parent_name, parent_entity


def intel_by_field(scan_id: int, domain: str, source: str, field: str) -> Optional[str]:
    """Reads back a single already-stored host_intel value — used by
    company_lookup's last-resort writeup fallback to check what
    social_scan (which runs earlier in the same pipeline) already found
    on the company's own About page."""
    conn = get_db()
    row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND host=? AND source=? AND field=?",
        (scan_id, domain, source, field),
    ).fetchone()
    conn.close()
    return row["value"] if row else None


async def company_lookup(
    scan_id: int, domain: str, name_candidates: list[str],
    user_supplied_name: Optional[str] = None, tld_variants: Optional[list[str]] = None,
):
    acceptable_domains = {domain}
    redirect_target = get_redirect_target_domain(scan_id)
    if redirect_target:
        acceptable_domains.add(redirect_target)

    # TLD variants (sensepost.com also checking sensepost.co.za, say) —
    # stored for visibility in the Company profile regardless of whether
    # any of them turn out to help confirm a Wikidata match, and ALSO
    # added to acceptable_domains so a variant that happens to be the
    # org's actual listed official website (rather than the domain this
    # scan started from) still counts as a match. If the caller already
    # discovered these (the Company-scan orchestrator now does this once
    # up front and shares the result with social_scan too, to avoid
    # doing the same DNS checks and "found N variant(s)" log line
    # twice), use that instead of re-discovering and re-logging here;
    # manual_company_lookup doesn't have that, so it still falls back to
    # discovering them itself exactly as before.
    discovered_here = tld_variants is None
    if discovered_here:
        tld_variants = await discover_tld_variants(domain)
    if tld_variants:
        acceptable_domains.update(tld_variants)
        # Only store/log this when WE discovered it — when the caller
        # passed its own already-discovered list (the Company-scan
        # orchestrator does this now, sharing one discovery with
        # social_scan too), the caller already stored and logged it
        # itself, and doing it again here would just duplicate both the
        # host_intel rows and the live-log line.
        if discovered_here:
            conn = get_db()
            for i, variant in enumerate(tld_variants):
                store_intel(conn, scan_id, domain, "company", f"tld_variant:{i}", variant)
            conn.commit()
            conn.close()
            await log_line(
                scan_id,
                f"[company] found {len(tld_variants)} other TLD variant(s) of this domain that resolve: "
                f"{', '.join(tld_variants)}",
                "meta",
            )

    tried_ids: set[str] = set()
    confirmed_entity = None
    confirmed_id = None
    matched_via = None

    for name in name_candidates:
        name = (name or "").strip()
        if not name or len(name) < 2:
            continue
        try:
            search_url = (
                f"https://www.wikidata.org/w/api.php?action=wbsearchentities"
                f"&search={urllib.parse.quote(name)}&language=en&format=json&type=item&limit=5"
            )
            search_data = await http_get_json(search_url, timeout=10)
        except Exception:
            continue
        for cand in search_data.get("search", []) or []:
            qid = cand.get("id")
            if not qid or qid in tried_ids:
                continue
            tried_ids.add(qid)
            try:
                entity_data = await http_get_json(
                    f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json", timeout=10
                )
            except Exception:
                continue
            entity = (entity_data.get("entities") or {}).get(qid)
            if not entity:
                continue
            for website in _wikidata_all_values(entity, "P856"):
                try:
                    host = urllib.parse.urlsplit(website).hostname or ""
                except Exception:
                    continue
                matched_domain = next((d for d in acceptable_domains if _host_matches_domain(host, d)), None)
                if matched_domain:
                    confirmed_entity, confirmed_id, matched_via = entity, qid, matched_domain
                    break
            if confirmed_entity:
                break
        if confirmed_entity:
            break

    if not confirmed_entity:
        # No Wikidata entity's own official-website claim matched either
        # the scanned domain or its redirect target (if any). Before
        # falling all the way back to a plain web search, try one more
        # thing when the person explicitly told us a company name (the
        # "Company name" field, or a manual lookup) — that's a much
        # higher-trust signal than anything guessed, and Wikidata's own
        # structured facts (industry, HQ, employee count, legal form)
        # are far richer than a DuckDuckGo text blurb, even without a
        # domain match to confirm it's definitely the same entity. This
        # is exactly the case a subsidiary of a large, multi-brand
        # parent hits: the parent's own Wikidata entry is real and
        # accurate, but only lists its own flagship domain as "official
        # website", not every subsidiary brand's domain — so the
        # domain-match check above never succeeds even when the name
        # match is completely correct (confirmed directly — this exact
        # scenario, a security consultancy's site now redirecting to its
        # acquirer's domain, with the acquirer's own Wikidata entry
        # never listing the subsidiary's domain). Stored and labeled as
        # a distinct, honest confidence tier ("name_matched") — not
        # blended in as if it were domain-verified, and not mislabeled
        # as a web search either, since it's genuinely from Wikidata.
        name_matched_entity = None
        name_matched_id = None
        clean_name = (user_supplied_name or "").strip()
        if clean_name:
            try:
                search_url = (
                    f"https://www.wikidata.org/w/api.php?action=wbsearchentities"
                    f"&search={urllib.parse.quote(clean_name)}&language=en&format=json&type=item&limit=1"
                )
                search_data = await http_get_json(search_url, timeout=10)
                top = (search_data.get("search") or [None])[0]
                if top and top.get("id"):
                    entity_data = await http_get_json(
                        f"https://www.wikidata.org/wiki/Special:EntityData/{top['id']}.json", timeout=10
                    )
                    entity = (entity_data.get("entities") or {}).get(top["id"])
                    if entity:
                        name_matched_entity, name_matched_id = entity, top["id"]
            except Exception:
                pass

        if name_matched_entity:
            facts = await _fetch_wikidata_facts(name_matched_entity)
            # Only worth using if it actually has something — an entity
            # with zero usable fields (a name collision with something
            # totally unrelated) is worse than no match at all.
            has_something = any([
                facts["headquarters"], facts["country"], facts["industry"], facts["legal_form"],
                facts["founded"], facts["employees"], facts["street_address"], facts["wiki_url"],
            ])
            if has_something:
                await log_line(
                    scan_id,
                    f"[company] no domain-confirmed Wikidata match, but '{clean_name}' matched {name_matched_id} by "
                    f"name — using its data, labeled as name-matched rather than domain-verified",
                    "meta",
                )
                conn = get_db()
                if facts["founded"]:
                    store_intel(conn, scan_id, domain, "company", "founded", facts["founded"])
                if facts["employees"]:
                    store_intel(conn, scan_id, domain, "company", "employees", facts["employees"])
                if facts["street_address"]:
                    store_intel(conn, scan_id, domain, "company", "street_address", facts["street_address"])
                for field in ("headquarters", "country", "industry", "legal_form"):
                    if facts[field]:
                        store_intel(conn, scan_id, domain, "company", field, facts[field])
                store_intel(conn, scan_id, domain, "company", "wikidata_id", name_matched_id)
                store_intel(conn, scan_id, domain, "company", "wikidata_match_confidence", "name_matched")
                if facts["wiki_url"]:
                    store_intel(conn, scan_id, domain, "company", "wikipedia", facts["wiki_url"])
                    if facts["extract"]:
                        store_intel(conn, scan_id, domain, "company", "writeup", facts["extract"])
                        store_intel(conn, scan_id, domain, "company", "writeup_confidence", "name_matched")
                        store_intel(conn, scan_id, domain, "company", "writeup_source", facts["wiki_url"])

                parent_result = await resolve_parent_org(name_matched_entity)
                if parent_result:
                    parent_qid, parent_name, parent_entity = parent_result
                    parent_facts = await _fetch_wikidata_facts(parent_entity)
                    store_intel(conn, scan_id, domain, "company", "parent_organization", parent_name)
                    store_intel(conn, scan_id, domain, "company", "parent_wikidata_id", parent_qid)
                    for field in ("headquarters", "country", "industry"):
                        if parent_facts[field]:
                            store_intel(conn, scan_id, domain, "company", f"parent_{field}", parent_facts[field])
                    if parent_facts["wiki_url"]:
                        store_intel(conn, scan_id, domain, "company", "parent_wikipedia", parent_facts["wiki_url"])
                    if parent_facts["extract"]:
                        store_intel(conn, scan_id, domain, "company", "parent_writeup", parent_facts["extract"])

                conn.commit()
                conn.close()
                return

        # Still nothing usable from Wikidata by any route — fall back to
        # a plain web search-style lookup instead of giving up entirely.
        # This is a genuinely different (weaker) confidence tier than
        # even the name-matched one above, so it's stored and later
        # displayed as such rather than blended in as if it were
        # equally certain. Tries the redirect target too if there is
        # one — a rebranded company's old domain often turns up nothing
        # useful on the open web anymore, while the current domain does.
        await log_line(
            scan_id,
            "[company] no Wikidata record confirmed by official-website or name match — trying a broader web search instead",
            "warn",
        )
        ddg = await duckduckgo_abstract(domain)
        abstract = (ddg or {}).get("AbstractText", "").strip()
        used_domain = domain
        if not abstract and redirect_target:
            ddg = await duckduckgo_abstract(redirect_target)
            abstract = (ddg or {}).get("AbstractText", "").strip()
            used_domain = redirect_target
        if abstract:
            conn = get_db()
            store_intel(conn, scan_id, domain, "company", "writeup", abstract)
            store_intel(conn, scan_id, domain, "company", "writeup_confidence", "unverified")
            if ddg.get("AbstractURL"):
                store_intel(conn, scan_id, domain, "company", "writeup_source", ddg["AbstractURL"])
            if ddg.get("Heading"):
                store_intel(conn, scan_id, domain, "company", "writeup_heading", ddg["Heading"])
            conn.commit()
            conn.close()
            note = f" (via {used_domain}, which this domain redirects to)" if used_domain != domain else ""
            await log_line(scan_id, f"[company] found a web write-up (unverified — name match only, not confirmed){note}", "meta")
            return

        # Nothing from Wikidata (by either route) or DuckDuckGo. Rather
        # than give up with no write-up at all, fall back to the
        # company's own About page — already scraped by social_scan,
        # which runs earlier in this same pipeline. This is deliberately
        # the last resort, not an earlier tier: Wikidata/DuckDuckGo are
        # at least somewhat independent of what the company says about
        # itself, while this is the company's own marketing copy,
        # unverified in every sense. But it doesn't depend on any
        # third-party database having coverage of this company at all —
        # which matters a lot here specifically. Wikidata's coverage has
        # a well-documented bias toward English-speaking, Western
        # subjects (most editors are from those regions), and DuckDuckGo's
        # instant-answer API draws from similar sources — so for a
        # company with no Wikipedia/Wikidata presence, which is common
        # and unremarkable rather than a sign of anything, both of those
        # tiers are likely to come up empty regardless of how real or
        # significant the company actually is. Reading what the company
        # published about itself directly sidesteps that gap entirely.
        about_text = intel_by_field(scan_id, domain, "social", "page:about:description")
        about_url = intel_by_field(scan_id, domain, "social", "page:about:url")
        if about_text:
            conn = get_db()
            store_intel(conn, scan_id, domain, "company", "writeup", about_text)
            store_intel(conn, scan_id, domain, "company", "writeup_confidence", "from_own_site")
            if about_url:
                store_intel(conn, scan_id, domain, "company", "writeup_source", about_url)
            conn.commit()
            conn.close()
            await log_line(
                scan_id,
                "[company] no Wikidata or web-search write-up either — using the company's own About page text instead",
                "meta",
            )
        else:
            await log_line(scan_id, "[company] nothing found on the open web either — no write-up available", "warn")
        return

    note = f" ({domain} redirects there)" if matched_via != domain else ""
    await log_line(scan_id, f"[company] confirmed Wikidata entity {confirmed_id} — official website matches {matched_via}{note}", "meta")

    facts = await _fetch_wikidata_facts(confirmed_entity)

    # Parent organization — the actual "X is now part of Y" signal this
    # was missing entirely before. Fetched (one hop) before opening the
    # DB connection, same "no network awaits between get_db() and
    # commit()/close()" discipline as everything else in this function —
    # that ordering is what avoids the "database is locked" class of bug
    # fixed elsewhere in this file (ip_geo_lookup, shodan_enrich_hosts).
    parent_result = await resolve_parent_org(confirmed_entity)
    parent_facts = None
    parent_name = None
    if parent_result:
        parent_qid, parent_name, parent_entity = parent_result
        parent_facts = await _fetch_wikidata_facts(parent_entity)

    conn = get_db()

    if facts["founded"]:
        store_intel(conn, scan_id, domain, "company", "founded", facts["founded"])
    if facts["employees"]:
        store_intel(conn, scan_id, domain, "company", "employees", facts["employees"])
    if facts["street_address"]:
        store_intel(conn, scan_id, domain, "company", "street_address", facts["street_address"])
    for field in ("headquarters", "country", "industry", "legal_form"):
        if facts[field]:
            store_intel(conn, scan_id, domain, "company", field, facts[field])

    if facts["wiki_url"]:
        store_intel(conn, scan_id, domain, "company", "wikipedia", facts["wiki_url"])
        if facts["extract"]:
            store_intel(conn, scan_id, domain, "company", "writeup", facts["extract"])
            store_intel(conn, scan_id, domain, "company", "writeup_confidence", "confirmed")
            store_intel(conn, scan_id, domain, "company", "writeup_source", facts["wiki_url"])
    store_intel(conn, scan_id, domain, "company", "wikidata_id", confirmed_id)
    store_intel(conn, scan_id, domain, "company", "wikidata_match_confidence", "confirmed")

    if parent_facts:
        store_intel(conn, scan_id, domain, "company", "parent_organization", parent_name)
        store_intel(conn, scan_id, domain, "company", "parent_wikidata_id", parent_qid)
        for field in ("headquarters", "country", "industry"):
            if parent_facts[field]:
                store_intel(conn, scan_id, domain, "company", f"parent_{field}", parent_facts[field])
        if parent_facts["wiki_url"]:
            store_intel(conn, scan_id, domain, "company", "parent_wikipedia", parent_facts["wiki_url"])
        if parent_facts["extract"]:
            store_intel(conn, scan_id, domain, "company", "parent_writeup", parent_facts["extract"])

    conn.commit()
    conn.close()

    if parent_facts:
        await log_line(scan_id, f"[company] this entity's own Wikidata record lists {parent_name} as its parent organization — fetched their details too", "meta")
    if facts["extract"]:
        await log_line(scan_id, "[company] public company record + Wikipedia write-up stored", "meta")
    else:
        await log_line(scan_id, "[company] public company record stored (no Wikipedia write-up available)", "meta")


# ---------------------------------------------------------------------------
# CrossLinked (github.com/m8sec/CrossLinked) — LinkedIn employee
# enumeration via Google/Bing search-engine scraping. No LinkedIn API or
# login needed, which is exactly why it's a good fit here — but it's the
# one tool this app wraps that writes its results to files (names.txt /
# names.csv) instead of printing them to stdout, so it needs its own
# integration rather than fitting the generic run_stream + parse pattern.
# ---------------------------------------------------------------------------
def _parse_crosslinked_csv(csv_path: Path) -> list[dict]:
    """Defensive parsing: CrossLinked's own docs describe the CSV as
    holding name/job-title/url per row, but don't guarantee an exact
    header spelling, so this tries to find header cells that look right
    and falls back to positional (name, title, url) if it can't."""
    if not csv_path.exists():
        return []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            raw_rows = list(csv.reader(f))
    except Exception:
        return []
    if not raw_rows:
        return []

    header = [h.strip().lower() for h in raw_rows[0]]
    has_header = any(h in ("name", "title", "job title", "url", "link", "profile") for h in header)
    data_rows = raw_rows[1:] if has_header else raw_rows
    name_idx = header.index("name") if has_header and "name" in header else 0
    title_idx = None
    if has_header:
        for candidate in ("title", "job title"):
            if candidate in header:
                title_idx = header.index(candidate)
                break
    if title_idx is None and len(header) > 1:
        title_idx = 1
    # Confirmed directly as a real gap: CrossLinked's CSV genuinely does
    # include a LinkedIn profile URL column (this function's own
    # docstring already said so), but nothing here ever read it — only
    # name/title were extracted, so every profile URL CrossLinked found
    # was silently discarded before it could reach storage or the UI.
    url_idx = None
    if has_header:
        for candidate in ("url", "link", "profile"):
            if candidate in header:
                url_idx = header.index(candidate)
                break
    if url_idx is None and len(header) > 2:
        url_idx = 2

    out = []
    for r in data_rows:
        if not r or len(r) <= name_idx:
            continue
        name = r[name_idx].strip()
        title = r[title_idx].strip() if title_idx is not None and len(r) > title_idx else ""
        url = r[url_idx].strip() if url_idx is not None and len(r) > url_idx else ""
        if name:
            out.append({"name": name, "title": title, "url": url})
    return out


async def crosslinked_run(scan_id: int, domain: str, mode: str, company_name: str) -> tuple[int, int]:
    """Returns (people_found, emails_found). Runs in a scan-scoped temp
    directory (both via `cwd` and an absolute `-o` path, so it lands in
    the right place regardless of whether CrossLinked's -o accepts a full
    path or just a filename) and is cleaned up afterward either way."""
    binary = shutil.which("crosslinked")
    if not binary:
        await log_line(scan_id, "[skip] crosslinked not found on PATH — skipping crosslinked", "warn")
        return 0, 0

    tmp_dir = BASE_DIR / f".scan_{scan_id}_crosslinked"
    tmp_dir.mkdir(exist_ok=True)
    out_base = tmp_dir / "names"

    # Safe default: plain "First Last" names, no assumed email pattern —
    # add a bespoke command variant (Tools sidebar -> crosslinked) with a
    # real -f pattern once you know the org's actual naming convention
    # (e.g. -f '{first}.{last}@yourdomain.com'); it overrides this default
    # since apply_variant's extra args are appended after it, and argparse
    # takes the last value when a flag is given twice.
    cmd = apply_variant(
        [binary, "-f", "{first} {last}", "-o", str(out_base), company_name],
        "crosslinked", mode,
    )
    await log_line(scan_id, f"[crosslinked] searching for '{company_name}' employees via Google/Bing...", "meta")
    people = 0
    emails_found = 0
    try:
        await run_stream(scan_id, cmd, "crosslinked", cwd=tmp_dir)

        csv_path = out_base.with_suffix(".csv")
        txt_path = out_base.with_suffix(".txt")
        if not csv_path.exists() and not txt_path.exists():
            # Neither output file exists at all — CrossLinked didn't just
            # find zero people, it never got to write anything, which
            # points at something failing before results: a crash, a
            # missing dependency, or (most commonly for this kind of
            # tool) Google/Bing serving a CAPTCHA instead of results.
            # Check the CrossLinked cheat sheet for --proxy/--proxy-file
            # if this keeps happening — search-engine scraping tools
            # often need IP rotation to stay reliable.
            await log_line(
                scan_id,
                "[crosslinked] no output files were produced at all — this usually means the run "
                "failed before writing results (a crash, or Google/Bing blocking the request with a "
                "CAPTCHA) rather than a genuine zero-employee search. Check the [out] lines above for "
                "the actual error, and consider a --proxy/--proxy-file variant if this repeats.",
                "warn",
            )

        rows = _parse_crosslinked_csv(csv_path)
        formatted_lines = []
        if txt_path.exists():
            formatted_lines = [
                l.strip() for l in txt_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()
            ]

        conn = get_db()
        # If the configured -f format looks like it produced emails (the
        # tool's own primary use case, per its README examples), store
        # them as emails — feeds the Emails tab directly rather than
        # sitting only in the intel dump.
        email_like = {l for l in formatted_lines if "@" in l}
        if email_like and len(email_like) >= len(formatted_lines) * 0.5:
            add_emails(conn, scan_id, email_like, "crosslinked")
            emails_found = len(email_like)

        # Always also store the raw name/title pairs — this is the actual
        # "who works there" OSINT value regardless of whether the -f
        # format happened to look like emails. field is per-person
        # (employee:<name>) so each gets its own host_intel row instead
        # of overwriting a shared "employee" key.
        capped = rows[:250]
        for r in capped:
            store_intel(conn, scan_id, domain, "crosslinked", f"employee:{r['name']}", r["title"] or "—")
            # Separate field, not appended into the title string — matches
            # this app's existing pattern of one field per distinct piece
            # of data (see phone:N/possible_staff_name:N in social_scan),
            # and keeps the LinkedIn URL cleanly retrievable on its own.
            if r.get("url"):
                store_intel(conn, scan_id, domain, "crosslinked", f"employee_url:{r['name']}", r["url"])
        people = len(rows)
        if len(rows) > len(capped):
            store_intel(conn, scan_id, domain, "crosslinked", "note", f"{len(rows)} employees found, showing first {len(capped)}")
        conn.commit()
        conn.close()

        both_files_existed = csv_path.exists() or txt_path.exists()
        if people == 0 and both_files_existed:
            await log_line(
                scan_id,
                f"[crosslinked] ran successfully but found 0 employees for '{company_name}' — the company "
                f"name guess is the most common reason (check Company Profile → click into this scan to "
                f"see what name was actually used; WHOIS org names behind privacy protection are filtered "
                f"out automatically, but the fallback guesses aren't always right either)",
                "warn",
            )
        await log_line(
            scan_id,
            f"[+] crosslinked: {people} employee(s) found for '{company_name}'"
            + (f", {emails_found} formatted as emails" if emails_found else ""),
            "meta",
        )
        return people, emails_found
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def crosslinked_run_multi(scan_id: int, domain: str, mode: str, primary_company_name: str) -> tuple[int, int]:
    """Runs crosslinked once per distinct company name worth searching —
    the primary guessed name, plus the parent organization's name if
    company_lookup found one (e.g. SensePost -> Orange Cyberdefense).
    A company that's been acquired or rebranded often has employees
    whose LinkedIn profiles list the new parent brand, the old brand, or
    both — searching only one name can genuinely miss real people.
    Reads the parent org name from host_intel rather than needing it
    passed in directly, so this only works correctly if company_lookup
    has already run for this scan — matches this app's own enrich-step
    ordering (company_lookup is registered before crosslinked in both
    the automatic pipeline and the manual company-scan trigger).

    People found under either name land in the same host_intel rows —
    store_intel's own upsert on (scan_id, host, source, field) handles
    de-duplication naturally, since the same person's name produces the
    same field key regardless of which search found them — so the
    counts returned here reflect distinct people actually stored, not a
    naive sum across searches that could double-count someone found
    both ways.
    """
    conn = get_db()
    parent_row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='company' AND field='parent_organization'",
        (scan_id,),
    ).fetchone()
    conn.close()

    names_to_search = [primary_company_name]
    parent_name = parent_row["value"] if parent_row else None
    if parent_name and parent_name.strip().lower() != primary_company_name.strip().lower():
        names_to_search.append(parent_name)

    if len(names_to_search) > 1:
        await log_line(
            scan_id,
            f"[crosslinked] a parent organization was found for this scan — searching under "
            f"{len(names_to_search)} company names: {', '.join(names_to_search)}",
            "meta",
        )

    for name in names_to_search:
        await crosslinked_run(scan_id, domain, mode, name)

    conn = get_db()
    people = conn.execute(
        "SELECT COUNT(*) as c FROM host_intel WHERE scan_id=? AND source='crosslinked' AND field LIKE 'employee:%'",
        (scan_id,),
    ).fetchone()["c"]
    emails = conn.execute(
        "SELECT COUNT(*) as c FROM emails WHERE scan_id=? AND source='crosslinked'", (scan_id,)
    ).fetchone()["c"]
    conn.close()
    return people, emails


# ---------------------------------------------------------------------------
# GDELT DOC 2.0 API — recent press/news mentions. Genuinely free, no
# signup, no key: confirmed directly (not assumed) that GDELT is a
# public, no-key, no-anti-bot API explicitly documented for exactly this
# kind of programmatic query — unlike Google News RSS, which works but
# rate-limits aggressively under automated use.
#
# This fills a real gap nothing else in the Company profile covers:
# what's recently *happened* to this organization — an acquisition, a
# funding round, a security incident, a leadership change — none of
# which shows up in a static Wikidata record. Deliberately scoped to a
# recent window (3 months) rather than GDELT's full archive; "recent
# press mentions" is the point, not a historical research dump.
# ---------------------------------------------------------------------------
def parse_gdelt_articles(data: dict) -> list[dict]:
    """Schema confirmed against several independent sources describing
    ArtList mode's actual output — url, url_mobile, title, seendate,
    socialimage, domain, language, sourcecountry — rather than guessed.
    Still defensive about a field being absent or malformed, since this
    wasn't verified against a live response from this sandbox (GDELT
    isn't reachable from here — see news_lookup)."""
    articles = data.get("articles")
    if not isinstance(articles, list):
        return []
    out = []
    for art in articles:
        if not isinstance(art, dict):
            continue
        title = (art.get("title") or "").strip()
        url = art.get("url") or ""
        if not title or not url:
            continue
        seendate = art.get("seendate") or ""
        # seendate looks like "20260115T120000Z" — reformat to a plain
        # date if it matches that shape, otherwise just show it as-is
        # rather than fail on a format that doesn't match expectations.
        display_date = seendate
        m = re.match(r"^(\d{4})(\d{2})(\d{2})T", seendate)
        if m:
            display_date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        out.append({
            "title": title,
            "url": url,
            "source": art.get("domain") or "",
            "date": display_date,
            "country": art.get("sourcecountry") or "",
        })
    return out


# ---------------------------------------------------------------------------
# Known-email enrichment — lets you feed in one or more real emails you
# already have for the org (from a previous engagement, a client contact,
# whatever). Two distinct things happen with them:
#   1. They're saved to this scan's Emails tab like any other source
#      (source="manual"), after the same off-domain filtering every other
#      email source goes through.
#   2. If a seed email's local-part structure matches a known CrossLinked
#      employee name (e.g. "jane.doe" against employee "Jane Doe"), that
#      confirms the org's actual naming convention — which then gets
#      applied to every *other* CrossLinked-found employee with no known
#      address, generating guessed (never claimed as confirmed) addresses
#      for the rest. This is the same capability the README already
#      pointed at as a manual CrossLinked `-f` variant — doing it here
#      automatically, from real evidence, instead of needing it
#      hand-configured, and without re-running CrossLinked at all.
# Hunter.io already detects and stores a pattern of its own
# (host_intel source="hunter" field="pattern", e.g. "{first}.{last}") but
# — confirmed by reading every call site — never actually applies it to
# anything; a real, previously-unused signal. Not wired in here since its
# token format isn't guaranteed to match EMAIL_PATTERN_TEMPLATES exactly,
# but worth revisiting if this gets used a lot.
# ---------------------------------------------------------------------------

# (template, human-readable label) — ordered roughly most-to-least common
# in the wild. {f}/{l} are first/last-initial shorthands for the ones
# below that don't use the full name.
EMAIL_PATTERN_TEMPLATES = [
    ("{first}.{last}", "firstname.lastname"),
    ("{first}_{last}", "firstname_lastname"),
    ("{first}-{last}", "firstname-lastname"),
    ("{first}{last}", "firstnamelastname"),
    ("{f}.{last}", "f.lastname"),
    ("{f}{last}", "flastname"),
    ("{first}.{l}", "firstname.l"),
    ("{first}{l}", "firstnamel"),
    ("{last}.{first}", "lastname.firstname"),
    ("{last}{first}", "lastnamefirstname"),
    ("{f}{l}", "initials"),
    ("{last}", "lastname"),
    ("{first}", "firstname"),
]
_EMAIL_PATTERN_LABELS = dict(EMAIL_PATTERN_TEMPLATES)


def _render_pattern(template: str, first: str, last: str) -> str:
    return template.format(first=first, last=last, f=first[:1], l=last[:1])


def _split_person_name(name: str) -> Optional[tuple[str, str]]:
    """First/last only — middle names are ignored since no template here
    accounts for one, and silently dropping it is safer than guessing
    which part of a 3+ word name actually maps to the email."""
    parts = [p for p in re.split(r"\s+", name.strip()) if re.sub(r"[^A-Za-z]", "", p)]
    if len(parts) < 2:
        return None
    first = re.sub(r"[^A-Za-z]", "", parts[0]).lower()
    last = re.sub(r"[^A-Za-z]", "", parts[-1]).lower()
    if not first or not last:
        return None
    return first, last


def detect_naming_pattern(local_part: str, first: str, last: str) -> Optional[str]:
    """Returns the matching template string (e.g. "{first}.{last}"), or
    None if this (first, last) pair doesn't render to local_part under
    any known template — a real non-match, not an error."""
    local_part = re.sub(r"[^a-z0-9._-]", "", local_part.lower())
    for template, _label in EMAIL_PATTERN_TEMPLATES:
        if _render_pattern(template, first, last) == local_part:
            return template
    return None


def _crosslinked_employee_names(scan_id: int) -> list[str]:
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT field FROM host_intel WHERE scan_id=? AND source='crosslinked' AND field LIKE 'employee:%'",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()
    return [r["field"][len("employee:"):] for r in rows]


def _guess_emails_for_employees(scan_id: int, domain: str, template: str) -> list[tuple[str, str]]:
    """Applies an already-detected template to every CrossLinked employee
    name that doesn't already have a known address (from any source) for
    this scan — returns [(name, guessed_email), ...] for the new ones
    only."""
    conn = get_db()
    try:
        existing = {
            r["email"].lower() for r in conn.execute("SELECT email FROM emails WHERE scan_id=?", (scan_id,)).fetchall()
        }
    finally:
        conn.close()
    guesses = []
    for name in _crosslinked_employee_names(scan_id):
        split = _split_person_name(name)
        if not split:
            continue
        first, last = split
        guessed = f"{_render_pattern(template, first, last)}@{domain}"
        if guessed.lower() in existing:
            continue
        guesses.append((name, guessed))
    return guesses


async def apply_known_emails(
    scan_id: int, domain: str, raw_emails: list[str], extra_domains: Optional[set[str]] = None
) -> dict:
    cleaned = {e.strip().lower() for e in raw_emails if e and e.strip()}
    if not cleaned:
        return {"accepted": [], "rejected": [], "pattern": None, "pattern_label": None, "guessed": []}

    valid = filter_emails_to_domain(cleaned, domain, extra_domains=extra_domains)
    rejected = sorted(cleaned - valid)
    accepted = sorted(valid)

    if accepted:
        conn = get_db()
        try:
            add_emails(conn, scan_id, set(accepted), "manual")
            conn.commit()
        finally:
            conn.close()

    employee_names = _crosslinked_employee_names(scan_id)

    # Try every accepted seed email against every known employee name —
    # first match wins. Good enough: in practice an org has one naming
    # convention, so the first confirmed match already tells us what it
    # is, and checking every pair is cheap (tens, not thousands).
    detected_template = None
    for email in accepted:
        local = email.split("@", 1)[0]
        for name in employee_names:
            split = _split_person_name(name)
            if not split:
                continue
            template = detect_naming_pattern(local, split[0], split[1])
            if template:
                detected_template = template
                break
        if detected_template:
            break

    guessed: list[tuple[str, str]] = []
    if detected_template:
        guessed = _guess_emails_for_employees(scan_id, domain, detected_template)
        if guessed:
            conn = get_db()
            try:
                add_emails(conn, scan_id, {addr for _, addr in guessed}, "pattern-guess")
                for name, addr in guessed:
                    store_intel(conn, scan_id, domain, "pattern-guess", f"employee_email:{name}", addr)
                conn.commit()
            finally:
                conn.close()

    detected_label = _EMAIL_PATTERN_LABELS.get(detected_template) if detected_template else None
    summary = f"[known-emails] {len(accepted)} seed email(s) accepted"
    if rejected:
        summary += f", {len(rejected)} rejected (not on {domain} or a known variant)"
    if detected_template:
        summary += f" — naming pattern confirmed as '{detected_label}', generated {len(guessed)} unverified guess(es) for other employees"
    elif employee_names:
        summary += " — no known employee name matched any seed email's format, so no pattern could be confirmed"
    else:
        summary += " — no CrossLinked employee names found yet to confirm a naming pattern against"
    await log_line(scan_id, summary, "meta" if detected_template else "warn")

    return {
        "accepted": accepted,
        "rejected": rejected,
        "pattern": detected_template,
        "pattern_label": detected_label,
        "guessed": [{"name": n, "email": a} for n, a in guessed],
    }


async def news_lookup(scan_id: int, domain: str, company_name: str):
    if not company_name or not company_name.strip():
        await log_line(scan_id, "[news] no company name to search for — skipped", "warn")
        return 0

    query = urllib.parse.quote(f'"{company_name.strip()}"')
    url = (
        f"https://api.gdeltproject.org/api/v2/doc/doc?query={query}"
        f"&mode=artlist&maxrecords=15&sort=DateDesc&timespan=3m&format=json"
    )
    try:
        data = await http_get_json(url, timeout=15)
    except Exception as e:
        # GDELT is known to occasionally return an HTML error page with
        # a 200 status instead of JSON (documented behavior of the
        # service itself, not something this app can control) — caught
        # here the same as any other failure rather than crashing on a
        # JSON-decode error specifically.
        await log_line(scan_id, f"[news] GDELT lookup failed: {e}", "warn")
        return 0

    articles = parse_gdelt_articles(data)
    if not articles:
        await log_line(scan_id, f"[news] no recent press mentions found for '{company_name}'", "meta")
        return 0

    conn = get_db()
    for art in articles:
        # Keyed by a hash of the URL, not a plain index — this function
        # gets called once per company name searched (primary, plus a
        # parent org if one was found), and a positional key would mean
        # the second call's "article:0" silently overwrites the first
        # call's via store_intel's own upsert-on-field-key behavior. A
        # URL-based key also gives free deduplication: the same article
        # turning up under both search terms only gets stored once.
        key = hashlib.sha256(art["url"].encode()).hexdigest()[:16]
        store_intel(conn, scan_id, domain, "news", f"article:{key}", json.dumps(art))
    conn.commit()
    conn.close()
    await log_line(scan_id, f"[+] news: {len(articles)} recent press mention(s) found for '{company_name}'", "meta")
    return len(articles)


# ---------------------------------------------------------------------------
# user-scanner (github.com/kaifcodec/user-scanner, `pip install
# user-scanner`) — username/email presence checking across a large set of
# third-party platforms. Deliberately NOT wired into the automatic
# Company-scan pipeline the way CrossLinked/Hunter.io/Shodan are: those
# are domain-scoped and either passive or a handful of requests; this is
# per-PERSON (a name or an email, not the domain) and even the curated
# "core" profile below is ~20 individual active HTTP requests against
# third-party sites for one identity — "full" breadth is thousands. That's
# a meaningfully louder, more active technique than anything else this
# app runs automatically, so it's a manual, per-identity trigger from the
# Company profile instead (see /api/scans/{id}/user-scanner in app.py),
# run once someone's actually worth checking rather than for every
# employee/email a scan happens to find.
#
# Module names below are exact, lowercase, confirmed directly against a
# real `pip install user-scanner` run (`user-scanner -lu`/`-le`), not
# guessed from the platform's display name — e.g. the X/Twitter module is
# literally named "x", not "twitter" (which errors: "User module
# 'twitter' not found"). Picked for being both widely recognizable AND
# relevant to confirming a real person tied to a company (dev platforms,
# major social networks) rather than the hundreds of niche wikis/forums/
# dating/adult modules this tool also carries — those stay available
# under the "full breadth" profile for anyone who wants them.
# ---------------------------------------------------------------------------
USER_SCANNER_CORE_USERNAME_MODULES = [
    "github", "githubgist", "gitlab", "bitbucket", "dockerhub", "npmjs", "pypi", "stackoverflow",
    "linkedin", "x", "facebook", "instagram", "mastodon", "reddit", "telegram", "youtube",
    "tiktok", "keybase", "discord",
]
USER_SCANNER_CORE_EMAIL_MODULES = [
    "github", "gravatar", "dropbox", "instagram", "facebook", "mastodon", "pinterest", "spotify",
    "amazon", "office365", "firefox", "hackerone", "hackthebox", "codepen", "wordpress",
]

# Terminal, non-hit statuses user-scanner itself reports — never counted
# as a found account. Matches the tool's own `--all` flag semantics
# (which exists specifically to *show* these; omitting it, as this app
# does, already suppresses them from the JSON... except the JSON export
# always includes every module checked regardless of --all, so this
# filter still has to happen on this app's side).
USER_SCANNER_NON_HIT_STATUSES = {"Not Found", "Not Registered", "Error", "Skipped"}


async def user_scanner_lookup(scan_id: int, identity_type: str, identity_value: str) -> list[dict]:
    """Runs user-scanner against ONE identity — identity_type is
    "username" (an employee name, typically from CrossLinked) or "email"
    (from the Emails tab, whatever source found it). Returns the list of
    actual hits (platforms where this identity has a confirmed or
    likely-confirmed presence), and persists them into host_intel the
    same way every other source does, keyed under a synthetic
    "person:<identity>" host since these findings belong to a person, not
    a hostname.

    Breadth (core vs. full) comes from this tool's own Profile picker in
    Settings (TOOL_PROFILES["user-scanner"]), same mechanism as
    SpiderFoot/nuclei — set once, applies to every check until changed,
    rather than asked again on every click.
    """
    binary = shutil.which("user-scanner")
    if not binary:
        await log_line(scan_id, "[skip] user-scanner not found on PATH — pip install user-scanner", "warn")
        return []

    profile = get_tool_profile("user-scanner", TOOL_PROFILES["user-scanner"]["default"])
    flag = "-u" if identity_type == "username" else "-e"
    core_modules = USER_SCANNER_CORE_USERNAME_MODULES if identity_type == "username" else USER_SCANNER_CORE_EMAIL_MODULES

    tmp_out = BASE_DIR / f".scan_{scan_id}_userscanner_{uuid.uuid4().hex[:12]}.json"
    cmd = [binary, flag, identity_value, "-f", "json", "-o", str(tmp_out), "-t", "10", "-C", "25"]
    if profile != "full":
        cmd += ["-m", ",".join(core_modules)]
    # "full" here (not "independent") matches the convention every other
    # independent-mode tool uses (see crosslinked_run_multi above) — the
    # variant "Applies to" picker in Settings only ever offers Fast/Full/
    # Both, so passing "full" is what makes a "Full only" or "Both modes"
    # variant actually apply; there's no distinct "independent" scope.
    cmd = apply_variant(cmd, "user-scanner", "full")

    breadth_desc = "core platform set" if profile != "full" else "full breadth (every module)"
    await log_line(scan_id, f"[user-scanner] checking {identity_type} '{identity_value}' against the {breadth_desc}...", "meta")
    # run_stream logs the actual "$ ..." command line itself (and looks up
    # this tool's "why" rationale) — no need to do either here.
    await run_stream(scan_id, cmd, "user-scanner")

    if not tmp_out.exists():
        await log_line(scan_id, f"[user-scanner] no output produced for {identity_value}", "warn")
        return []

    try:
        data = json.loads(tmp_out.read_text())
    except Exception as e:
        await log_line(scan_id, f"[error] user-scanner: failed to parse output for {identity_value}: {e}", "error")
        return []
    finally:
        tmp_out.unlink(missing_ok=True)

    hits = [r for r in data if r.get("status") not in USER_SCANNER_NON_HIT_STATUSES]

    conn = get_db()
    try:
        person_host = f"person:{identity_value}"
        for r in hits:
            site = r.get("site_name") or "unknown"
            url = r.get("url") or ""
            store_intel(conn, scan_id, person_host, "user-scanner", f"platform:{site}", url)
        conn.commit()
    finally:
        conn.close()

    await log_line(
        scan_id,
        f"[+] user-scanner: {len(hits)} account(s)/registration(s) found for {identity_value}"
        f" ({len(data)} checked)",
        "meta",
    )
    return hits
