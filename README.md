# N0aziXss Secure Crawl 🍓

Advanced Web Security Scanner and Crawler.

## Key Features ✨
- Automated website crawling
- Parameterized URL detection
- Security token and cookie collection
- HTTP header extraction
- Professional JSON reporting

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com/NazaninNazari/Secure_Crawl.git
cd Secure_Crawl-tools

# install dependencies
pip install -r requirements.txt

#Usage
python secure_crawl.py

# Sample Output
Enter target URL: example.com

Scanning: https://example.com
[»] Crawling: https://example.com

=== SCAN RESULTS ===
Total URLs found: 42
URLs with parameters: 7 
Important cookies: 3
Security tokens detected: 2
HTTP headers collected: 12
Errors encountered: 1

=== KEY FINDINGS ===
1. Login page: https://example.com/login
2. Search with params: https://example.com/search?q=test
3. Admin cookie: sessionid=ABC123...
4. JWT token: eyJhbGciOiJIUzI1NiIsInR5...

Scan completed. Full results saved to scan_results_example.com_20240515.json