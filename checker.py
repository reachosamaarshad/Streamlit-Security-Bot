import requests
import socket
import ssl
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta
import time
import json

# Optional imports with error handling
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class SecurityChecker:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm',
            'bank', 'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
            'netflix', 'spotify', 'dropbox', 'linkedin', 'twitter', 'instagram'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        
        # Headers to mimic a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def analyze_url(self, url):
        """Main method to analyze URL security"""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            results = {
                'url': url,
                'domain': domain,
                'findings': {},
                'recommendations': [],
                'overall_score': 0
            }
            
            # Perform all security checks
            results['findings']['HTTPS & SSL'] = self.check_https_ssl(url)
            results['findings']['Domain Analysis'] = self.check_domain_security(domain)
            results['findings']['Network Security'] = self.check_network_security(domain)
            results['findings']['Content Security'] = self.check_content_security(url)
            results['findings']['Headers Security'] = self.check_security_headers(url)
            
            # Calculate overall score
            results['overall_score'] = self.calculate_overall_score(results['findings'])
            
            # Generate recommendations
            results['recommendations'] = self.generate_recommendations(results['findings'])
            
            return results
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'findings': {},
                'recommendations': ['Unable to complete analysis due to an error'],
                'overall_score': 0
            }

    def check_https_ssl(self, url):
        """Check HTTPS usage and SSL certificate validity"""
        findings = []
        
        try:
            # Check if HTTPS is used
            if url.startswith('https://'):
                findings.append({
                    'status': 'pass',
                    'message': 'HTTPS is properly configured'
                })
            else:
                findings.append({
                    'status': 'fail',
                    'message': 'Website does not use HTTPS - data transmission is not encrypted'
                })
            
            # Check SSL certificate
            if url.startswith('https://'):
                parsed_url = urlparse(url)
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed_url.netloc, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check certificate expiration
                            if cert and 'notAfter' in cert:
                                not_after_str = cert['notAfter']
                                if isinstance(not_after_str, str):
                                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                                    days_until_expiry = (not_after - datetime.now()).days
                                    
                                    if days_until_expiry > 30:
                                        findings.append({
                                            'status': 'pass',
                                            'message': f'SSL certificate is valid and expires in {days_until_expiry} days'
                                        })
                                    elif days_until_expiry > 0:
                                        findings.append({
                                            'status': 'warning',
                                            'message': f'SSL certificate expires in {days_until_expiry} days'
                                        })
                                    else:
                                        findings.append({
                                            'status': 'fail',
                                            'message': 'SSL certificate has expired'
                                        })
                            
                            # Check certificate issuer
                            if cert and 'issuer' in cert:
                                issuer = cert['issuer']
                                if isinstance(issuer, tuple):
                                    # Convert tuple format to dict
                                    issuer_dict = {}
                                    for item in issuer:
                                        if isinstance(item, tuple) and len(item) == 2:
                                            issuer_dict[item[0]] = item[1]
                                    
                                    if 'commonName' in issuer_dict:
                                        findings.append({
                                            'status': 'pass',
                                            'message': f'SSL certificate issued by: {issuer_dict["commonName"]}'
                                        })
                                
                except Exception as e:
                    findings.append({
                        'status': 'fail',
                        'message': f'SSL certificate validation failed: {str(e)}'
                    })
            
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Error checking HTTPS/SSL: {str(e)}'
            })
        
        return findings

    def check_domain_security(self, domain):
        """Check domain age, registration, and suspicious patterns"""
        findings = []
        
        try:
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                findings.append({
                    'status': 'warning',
                    'message': f'Domain uses suspicious TLD: {domain}'
                })
            
            # Check domain age using WHOIS
            if WHOIS_AVAILABLE:
                try:
                    w = whois.whois(domain)
                    
                    if w and w.creation_date:
                        creation_date = w.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        
                        if creation_date:
                            domain_age = (datetime.now() - creation_date).days
                            
                            if domain_age > 365:
                                findings.append({
                                    'status': 'pass',
                                    'message': f'Domain is {domain_age} days old (established)'
                                })
                            elif domain_age > 30:
                                findings.append({
                                    'status': 'warning',
                                    'message': f'Domain is relatively new ({domain_age} days old)'
                                })
                            else:
                                findings.append({
                                    'status': 'fail',
                                    'message': f'Domain is very new ({domain_age} days old) - potential risk'
                                })
                        else:
                            findings.append({
                                'status': 'warning',
                                'message': 'Unable to determine domain age'
                            })
                    else:
                        findings.append({
                            'status': 'warning',
                            'message': 'Unable to retrieve domain registration info'
                        })
                        
                except Exception as e:
                    findings.append({
                        'status': 'warning',
                        'message': f'Unable to retrieve domain registration info: {str(e)}'
                    })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'WHOIS library not available - domain age check skipped'
                })
            
            # Check for suspicious keywords in domain
            domain_lower = domain.lower()
            suspicious_found = [kw for kw in self.suspicious_keywords if kw in domain_lower]
            
            if suspicious_found:
                findings.append({
                    'status': 'warning',
                    'message': f'Domain contains suspicious keywords: {", ".join(suspicious_found)}'
                })
            
            # Check for IP address in domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                findings.append({
                    'status': 'fail',
                    'message': 'Domain is an IP address - potential security risk'
                })
            
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Error in domain analysis: {str(e)}'
            })
        
        return findings

    def check_network_security(self, domain):
        """Check DNS resolution and network security"""
        findings = []
        
        try:
            # Check if domain resolves to IP
            try:
                ip_addresses = socket.gethostbyname_ex(domain)
                findings.append({
                    'status': 'pass',
                    'message': f'Domain resolves to IP addresses: {", ".join(ip_addresses[2])}'
                })
                
                # Check for private IP addresses
                for ip in ip_addresses[2]:
                    if ip.startswith(('10.', '172.16.', '192.168.')):
                        findings.append({
                            'status': 'warning',
                            'message': f'Domain resolves to private IP: {ip}'
                        })
                        
            except socket.gaierror:
                findings.append({
                    'status': 'fail',
                    'message': 'Domain does not resolve to any IP address'
                })
            
            # Check for DNS records
            if DNS_AVAILABLE:
                try:
                    # Check for SPF record
                    try:
                        dns.resolver.resolve(domain, 'TXT')
                        findings.append({
                            'status': 'pass',
                            'message': 'DNS TXT records found (may include SPF)'
                        })
                    except:
                        findings.append({
                            'status': 'warning',
                            'message': 'No DNS TXT records found (missing SPF record)'
                        })
                        
                except Exception as e:
                    findings.append({
                        'status': 'warning',
                        'message': f'Unable to check DNS records: {str(e)}'
                    })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'DNS library not available - DNS record check skipped'
                })
                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Error in network analysis: {str(e)}'
            })
        
        return findings

    def check_content_security(self, url):
        """Check website content for security indicators"""
        findings = []
        
        try:
            # Try to fetch the webpage
            response = requests.get(url, headers=self.headers, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for security-related content
                security_indicators = [
                    'privacy policy', 'terms of service', 'security', 'ssl', 'https',
                    'encryption', 'secure', 'trust', 'certificate'
                ]
                
                found_indicators = [ind for ind in security_indicators if ind in content]
                
                if found_indicators:
                    findings.append({
                        'status': 'pass',
                        'message': f'Security-related content found: {", ".join(found_indicators[:3])}'
                    })
                else:
                    findings.append({
                        'status': 'warning',
                        'message': 'No obvious security-related content found'
                    })
                
                # Check for forms (potential data collection)
                if '<form' in content:
                    findings.append({
                        'status': 'warning',
                        'message': 'Website contains forms - verify data collection practices'
                    })
                    
            else:
                findings.append({
                    'status': 'warning',
                    'message': f'Website returned status code: {response.status_code}'
                })
                
        except requests.exceptions.RequestException as e:
            findings.append({
                'status': 'fail',
                'message': f'Unable to access website content: {str(e)}'
            })
        
        return findings

    def check_security_headers(self, url):
        """Check for important security headers"""
        findings = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            headers = response.headers
            
            # Check for HSTS header
            if 'strict-transport-security' in headers:
                findings.append({
                    'status': 'pass',
                    'message': 'HSTS header present - enforces HTTPS'
                })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'HSTS header missing - should enforce HTTPS'
                })
            
            # Check for X-Frame-Options
            if 'x-frame-options' in headers:
                findings.append({
                    'status': 'pass',
                    'message': 'X-Frame-Options header present - prevents clickjacking'
                })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'X-Frame-Options header missing - vulnerable to clickjacking'
                })
            
            # Check for X-Content-Type-Options
            if 'x-content-type-options' in headers:
                findings.append({
                    'status': 'pass',
                    'message': 'X-Content-Type-Options header present - prevents MIME sniffing'
                })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'X-Content-Type-Options header missing'
                })
            
            # Check for Content-Security-Policy
            if 'content-security-policy' in headers:
                findings.append({
                    'status': 'pass',
                    'message': 'Content Security Policy header present'
                })
            else:
                findings.append({
                    'status': 'warning',
                    'message': 'Content Security Policy header missing'
                })
                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Unable to check security headers: {str(e)}'
            })
        
        return findings

    def calculate_overall_score(self, findings):
        """Calculate overall security score based on findings"""
        total_points = 0
        max_points = 0
        
        for category, category_findings in findings.items():
            for finding in category_findings:
                max_points += 10
                if finding['status'] == 'pass':
                    total_points += 10
                elif finding['status'] == 'warning':
                    total_points += 5
                # fail gets 0 points
        
        if max_points == 0:
            return 0
        
        return min(100, int((total_points / max_points) * 100))

    def generate_recommendations(self, findings):
        """Generate recommendations based on findings"""
        recommendations = []
        
        for category, category_findings in findings.items():
            for finding in category_findings:
                if finding['status'] == 'fail':
                    if 'HTTPS' in category:
                        recommendations.append('Enable HTTPS and obtain a valid SSL certificate')
                    elif 'Domain' in category:
                        recommendations.append('Verify domain legitimacy and registration details')
                    elif 'Network' in category:
                        recommendations.append('Ensure proper DNS configuration and resolution')
                    elif 'Headers' in category:
                        recommendations.append('Implement missing security headers')
                elif finding['status'] == 'warning':
                    if 'SSL' in finding.get('message', ''):
                        recommendations.append('Renew SSL certificate before expiration')
                    elif 'HSTS' in finding.get('message', ''):
                        recommendations.append('Implement HSTS header for better security')
                    elif 'Domain' in category and 'new' in finding.get('message', ''):
                        recommendations.append('Exercise caution with newly registered domains')
        
        # Remove duplicates and limit to top recommendations
        unique_recommendations = list(set(recommendations))
        return unique_recommendations[:5]  # Return top 5 recommendations 