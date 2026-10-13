# Email Finder

A small command-line tool that finds contact emails for a company domain, so you can apply for jobs. It works for free with no API keys. Paid services (Hunter.io, Omkar Cloud, SerpApi) are optional extras.

## Setup

1. Install Python 3.8 or newer.
2. Install the required packages:
   
   ```
   py -m pip install requests dnspython beautifulsoup4
   ```
3. Optional packages:
   
   ```
   py -m pip install mailscout
   py -m pip install google-search-results
   ```
   
   - `mailscout` improves the SMTP mailbox checks.
   - `google-search-results` is only needed if you use SerpApi.

## Usage

```
py main.py
```

Type a domain at the prompt (for example `company.com`) and press Enter. Type `q` to quit.

For each domain the tool will:

1. Check that the domain can receive email (MX records).
2. Crawl the company's website and collect published emails, including hidden ones such as `name [at] site [dot] com` and Cloudflare-protected addresses. It also reads structured data on the page and `security.txt`.
3. Look for linked job boards (Greenhouse, Lever, Ashby, Workable and others) and list open roles where a public feed exists.
4. Work out the company's email format (such as `first.last@`) from the addresses it found. If you type a recruiter's full name when asked, it builds their likely address.
5. Check common addresses such as `jobs@` and `careers@`.
6. Save everything to `emails.csv`.

## Reading the results

The `status` column in `emails.csv` tells you how much to trust each address:

| Status | Meaning |
| --- | --- |
| `FOUND_ON_SITE` | Published on the company's own website. Most reliable. |
| `FOUND_ON_SECURITY_TXT` | Listed in `security.txt`. Usually a security contact, not HR. |
| `FOUND_VIA_SERPAPI` | Found on a page discovered through SerpApi. |
| `FROM_HUNTER` / `FROM_OMKAR` | Returned by those services. |
| `VERIFIED` | The mail server confirmed the mailbox exists. |
| `PATTERN_INFERRED` | Built from the company's email format and a name you gave. Not confirmed. |
| `UNVERIFIED_GUESS` | A guess that could not be checked. It may bounce. |

## Optional API keys

Set these environment variables before running (PowerShell):

```
$env:HUNTER_API_KEY="your_key"
$env:OMKAR_API_KEY="your_key"
$env:SERPAPI_API_KEY="your_key"
```

Any key you leave unset is simply skipped.

## Limits

- **SMTP checks:** most home and cloud networks block outbound port 25, so many guesses will show as `UNVERIFIED_GUESS`. You can set `ENABLE_SMTP_VERIFY = False` in the script to turn the checks off.
- **Catch-all domains:** some domains accept mail for any address. The tool skips guessing for these because a "found" result would prove nothing.
- **Coverage:** the tool only finds what a company publishes. Many companies publish only `info@` or `contact@`.
- **Applying:** a job board application or a named recruiter usually gets a better response than a guessed `hr@` address.

## Responsible use

- The crawler respects `robots.txt` and waits between requests. Keep the defaults and don't crank up the crawl limits.
- Use the tool for individual, relevant job applications. Don't use it for bulk mailing. Spam laws such as New Zealand's Unsolicited Electronic Messages Act apply.
- Don't use it to collect personal emails for purposes other than your own job search.

