# Code Hunter v2
A permission-scoped crawler and OCR scanner. Use only where both the site operator and any applicable campaign rules permit automated scanning. It does not submit or validate codes, log in, evade restrictions, or follow redirects. robots.txt is checked per origin and inaccessible robots.txt blocks crawling. Requests are sequential with a minimum 3-second interval; HTTP 429/503 stops the run. Default 100 queued items, maximum 500 per invocation (pages, sitemaps, images and blocked items count).

## Ubuntu
```bash
sudo apt update
sudo apt install -y python3-venv tesseract-ocr tesseract-ocr-eng
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Authorized website example
```bash
python crawler.py --start https://example.org/ --sitemap https://example.org/sitemap.xml --permission-confirmed
```
Use `--permission-confirmed` only after verifying permission. For a CDN explicitly permitted for scanning, add `--image-host cdn.example.org` (repeat for multiple hosts). Same-host HTTPS links only for pages and sitemaps. Sitemap index and plain XML supported; compressed sitemaps, JavaScript-rendered galleries, CSS backgrounds, authentication, redirects and external links are not supported. Image OCR can miss text or return false positives. Text hits and OCR candidates are not verified discounts. `--max-items 100` sets the number of queue items per run. Run the same command using the same `--db` to resume pending items. Use a separate database per website. No automatic rescanning of completed pages.

Output: `crawl.sqlite3` (queue, results, sources, image cache), `results.jsonl` (all candidate codes, source URLs, OCR coordinates/confidence when available). Logs to stderr. The original local scanner is also provided: `python hunter.py images --watch`.

Tests: offline HTML extraction, URL normalization, regex, and syntax checked. Full network integration and target website not tested; Protego must be installed using requirements.txt.
