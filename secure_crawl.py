import re
import requests
import json
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from pyfiglet import Figlet
from colorama import Fore, init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime

# Initialize
init(autoreset=True)
console = Console()

# Banner
BANNER = Figlet(font='slant').renderText('Secure Crawl')
console.print(Fore.CYAN + BANNER)
print(Fore.YELLOW + "♦*"*15)
print(Fore.CYAN + "🍓N0aziXss Secure Crawl v3.0🍓")
print(Fore.YELLOW + "♦*"*15 + "\n")

class URLScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.all_urls = set()
        self.param_urls = set()
        self.cookies = {}
        self.tokens = {}
        self.headers_data = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        })
        self.timeout = 10
        self.error_count = 0
        
        self.token_patterns = [
            r'(?i)(token|auth|session|access|refresh)[_\-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'(?i)(token|auth|session|access|refresh)[_\-]?(id|secret)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'[a-zA-Z0-9_\-]{24,}\.[a-zA-Z0-9_\-]{6,}\.[a-zA-Z0-9_\-]{27,}',
            r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            r'(?i)(api|secret|private|public)[_\-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-@#$%^&*]{8,})[\'"]?',
            r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[\'"]?([A-Z0-9]{20,})[\'"]?',
            r'(?i)(google|gcp)[_\-]?api[_\-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'(?i)(db|database)[_\-]?(user|name|pass|host|port)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',
            r'(?i)(encryption|decryption|secret)_key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
            r'(?i)(salt|iv|nonce)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{8,})[\'"]?',
            r'(?i)(admin|root|superuser)[_\-]?(user|pass|credential)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]+)[\'"]?'
        ]

    def has_parameters(self, url):
        try:
            return bool(parse_qs(urlparse(str(url)).query))
        except:
            return False

    def is_valid_url(self, url):
        try:
            parsed = urlparse(str(url))
            base_parsed = urlparse(self.base_url)
            return (parsed.netloc == base_parsed.netloc and 
                    parsed.scheme in ('http', 'https'))
        except:
            return False

    def extract_security_items(self, url, response):
        for cookie in response.cookies:
            cookie_str = f"{cookie.name}={cookie.value}"
            if cookie_str not in self.cookies:
                self.cookies[cookie_str] = url
        
        for pattern in self.token_patterns:
            matches = re.finditer(pattern, response.text)
            for match in matches:
                token = match.group()
                if token not in self.tokens:
                    self.tokens[token] = url

        self.headers_data[url] = dict(response.headers)

    def extract_links(self, url):
        try:
            url = str(url)
            if not url.startswith(('http://', 'https://')):
                return

            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                response.raise_for_status()
            except requests.exceptions.HTTPError as http_err:
                self.error_count += 1
                console.print(f" [✗] [yellow]HTTP {http_err.response.status_code}[/yellow] at {url}")
                return
            except requests.exceptions.RequestException as req_err:
                self.error_count += 1
                console.print(f" [✗] [yellow]Connection Error[/yellow] at {url} - {type(req_err).__name__}")
                return

            self.extract_security_items(url, response)

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href'].strip()
                if href.lower().startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
                    continue
                
                full_url = urljoin(url, href.split('#')[0])
                full_url = full_url.rstrip('/')
                
                if self.is_valid_url(full_url):
                    self.all_urls.add(str(full_url))
                    if self.has_parameters(full_url):
                        self.param_urls.add(str(full_url))

        except Exception as e:
            self.error_count += 1
            console.print(f" [✗] [red]Error processing {url}: {type(e).__name__}[/red]")

    def crawl(self, max_pages=50):
        queue = [self.base_url]
        
        while queue and len(self.visited_urls) < max_pages:
            current_url = queue.pop(0)
            
            if current_url not in self.visited_urls:
                # console.print(f" [»] Crawling: {textwrap.shorten(current_url, width=70, placeholder='...')}")
                console.print(f" [»] Crawling: {current_url}")
                self.visited_urls.add(str(current_url))
                self.extract_links(current_url)
                
                new_urls = [u for u in self.all_urls if u not in self.visited_urls and u not in queue]
                queue.extend(new_urls)

    def get_results(self):
        return {
            'all': sorted([str(url) for url in self.all_urls if url is not None], 
                         key=lambda x: urlparse(x).path),
            'with_params': sorted([str(url) for url in self.param_urls if url is not None],
                                 key=lambda x: urlparse(x).path),
            'cookies': self.cookies,
            'tokens': self.tokens,
            'headers': self.headers_data,
            'error_count': self.error_count
        }

    def save_to_json(self, results):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        domain = urlparse(self.base_url).netloc.replace('.', '_')
        filename = f"scan_results_{domain}_{timestamp}.json"
        
        report = {
            "scan_info": {
                "target": self.base_url,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_urls": len(results['all']),
                "urls_with_params": len(results['with_params']),
                "cookies_found": len(results['cookies']),
                "tokens_found": len(results['tokens']),
                "headers_found": len(results['headers']),
                "errors_encountered": results['error_count'],
                "status": "completed"
            },
            "details": results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        console.print(Panel.fit(
            f"[bold green]✓ Scan results saved to [cyan]{filename}[/cyan][/bold green]",
            border_style="green"
        ))

    def display_headers(self):
        if not self.headers_data:
            console.print(Panel.fit("[yellow]No headers found[/yellow]",
                                  border_style="yellow"))
            return
        
        for url, headers in self.headers_data.items():
            console.print(Panel.fit(f"[bold]Headers for: [cyan]{url}[/cyan][/bold]",
                                  border_style="blue"))
            
            header_table = Table(show_header=True, header_style="purple")
            header_table.add_column("Header", style="dim")
            header_table.add_column("Value")
            
            for header, value in headers.items():
                header_table.add_row(header, str(value))
            
            console.print(header_table)

def display_section(title, color="blue"):
    console.print(Panel.fit(
        f"[bold {color}]{title}[/bold {color}]",
        border_style=color
    ))

def display_urls(title, items):
    if not items:
        console.print(f"[yellow]No {title.lower()} found[/yellow]")
        return
    
    table = Table(
        title=f"[bold]{title}[/bold]",
        show_header=True,
        header_style="bold magenta",
        show_lines=True
    )
    table.add_column("No.", style="dim", width=6)
    table.add_column("URL", style="cyan")
    
    for i, item in enumerate(items, 1):
        table.add_row(str(i), str(item))
    
    console.print(table)

def display_findings(title, items):
    if not items:
        console.print(f"[yellow]No {title.lower()} found[/yellow]")
        return
    
    for i, (item, source) in enumerate(items.items(), 1):
        console.print(f"\n[bold cyan]{i}.[/bold cyan] [red]{item}[/red]")
        console.print(f"   [dim]Source:[/dim] {source}")

if __name__ == "__main__":
    try:
        target = console.input("\n[cyan]»[/cyan] Enter target URL: ").strip()
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        display_section(f"Scanning: {target}")
        
        scanner = URLScanner(target)
        scanner.crawl(max_pages=100)
        results = scanner.get_results()

        # Display summary
        summary_table = Table(
            title="[bold]Scan Summary[/bold]",
            show_header=True,
            header_style="yellow"
        )
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="magenta")
        
        summary_data = [
            ("Total URLs", len(results['all'])),
            ("URLs with Parameters", len(results['with_params'])),
            ("Cookies Found", len(results['cookies'])),
            ("Tokens Found", len(results['tokens'])),
            ("Headers Collected", len(results['headers'])),
            ("Errors Encountered", results['error_count'])
        ]
        
        for metric, value in summary_data:
            summary_table.add_row(metric, str(value))
        
        console.print(summary_table)

        # Display detailed results
        if results['all']:
            display_urls("Discovered URLs", results['all'])
            
            if results['with_params']:
                display_urls("URLs with Parameters", results['with_params'])
            
            if results['cookies']:
                display_section("Discovered Cookies", "yellow")
                display_findings("Cookies", results['cookies'])
            
            if results['tokens']:
                display_section("Potential Tokens", "yellow")
                display_findings("Tokens", results['tokens'])
            
            # Display headers
            scanner.display_headers()
            
            scanner.save_to_json(results)
            
            display_section("Scan Completed Successfully", "green")
        else:
            display_section("No URLs Found", "red")

    except KeyboardInterrupt:
        display_section("Scan Cancelled by User", "red")
    except Exception as e:
        display_section(f"Fatal Error: {str(e)}", "red")