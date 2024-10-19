# Extract URLs from Text or Emails
import re
import tldextract

# Extract URLs from text (email body or plain text)
def extract_urls(text):
    url_pattern = r'(https?://[^\s\'",>]+)'
    return re.findall(url_pattern, text)

# Check if URL uses an IP address
def is_ip_address(url):
    ip_pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    return bool(re.match(ip_pattern, url))

# Check if URL has a suspicious domain name
def suspicious_domain(url):
    domain_info = tldextract.extract(url)
    domain = domain_info.domain
    # Example heuristic: domains with numbers or "secure" are suspicious
    if re.search(r'\d', domain) or 'secure' in domain.lower():
        return True
    return False

# Check if URL is too long
def url_too_long(url, max_length=100):
    return len(url) > max_length

# Scoring System for URL phishing detection
def score_url(url):
    score = 0
    if is_ip_address(url):
        score += 3
    if suspicious_domain(url):
        score += 3  # Increased score for suspicious domains
    if url_too_long(url):
        score += 1
    return score

# Analyze list of URLs for phishing characteristics
def analyze_urls(urls):
    phishing_urls = []
    for url in urls:
        score = score_url(url)
        print(f"URL: {url} | Score: {score}")  # Print the score for debugging
        if score >= 3:  # Lower threshold for flagging phishing
            phishing_urls.append((url, score))
    return phishing_urls

# Generate a report of suspicious URLs
def generate_report(phishing_urls, report_file='phishing_report.txt'):
    with open(report_file, 'w') as f:
        f.write("Phishing URL Detection Report\n")
        f.write("=" * 40 + "\n")
        for url, score in phishing_urls:
            f.write(f"URL: {url}\nScore: {score}\nStatus: Suspicious\n\n")

# Example usage
if __name__ == "__main__":
    # Sample text with URLs for testing
    sample_text = """
    Check out this website: http://example.com
    Here’s another one: https://123.45.67.89/login
    And a suspicious link: http://g00gle.com/secure-login
    """

    # Extract and analyze URLs
    urls = extract_urls(sample_text)
    phishing_urls = analyze_urls(urls)
    
    # Generate report
    generate_report(phishing_urls)
    print("Phishing URL detection complete. Report generated.")
