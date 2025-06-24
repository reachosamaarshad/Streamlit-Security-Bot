import requests
import socket
import ssl
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta
import time
import json
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

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

class AdvancedSecurityChecker:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm',
            'bank', 'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
            'netflix', 'spotify', 'dropbox', 'linkedin', 'twitter', 'instagram'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        
        # Common malicious patterns
        self.malicious_patterns = [
            r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'is\.gd', r'cli\.gs',
            r'ow\.ly', r'u\.to', r'j\.mp', r'3\.ly', r'qkme\.me',
            r'decenturl\.com', r'snipurl\.com', r'short\.to', r'BudURL\.com',
            r'ping\.fm', r'post\.ly', r'Just\.as', r'bkite\.com', r'snipr\.com',
            r'fic\.kr', r'loopt\.us', r'doiop\.com', r'dis\.co', r'short\.ie',
            r'kl\.am', r'wp\.me', r'rubyurl\.com', r'om\.ly', r'to\.ly',
            r'bit\.do', r't\.co', r'lnkd\.in', r'db\.tt', r'qr\.ae',
            r'adf\.ly', r'goo\.gl', r'bitly\.com', r'cur\.lv', r'tinyurl\.com',
            r'ow\.ly', r'bit\.ly', r'ad\.fly', r'bit\.ly', r'lnkd\.in'
        ]
        
        # Headers to mimic a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Common ports to scan
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        # Security header standards
        self.security_headers = {
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'content-security-policy': 'CSP',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'cross-origin-embedder-policy': 'COEP',
            'cross-origin-opener-policy': 'COOP',
            'cross-origin-resource-policy': 'CORP'
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
            results['findings']['Advanced SSL/TLS'] = self.check_advanced_ssl(url)
            results['findings']['Malware Detection'] = self.check_malware_indicators(url, domain)
            results['findings']['Port Security'] = self.check_port_security(domain)
            results['findings']['DNS Security'] = self.check_dns_security(domain)
            results['findings']['Email Security'] = self.check_email_security(domain)
            results['findings']['Web App Security'] = self.check_webapp_security(url)
            
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

    def check_advanced_ssl(self, url):
        """Advanced SSL/TLS analysis"""
        findings = []
        
        try:
            parsed_url = urlparse(url)
            if url.startswith('https://'):
                context = ssl.create_default_context()
                with socket.create_connection((parsed_url.netloc, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        # Check TLS version
                        if 'TLSv1.3' in version:
                            findings.append({
                                'status': 'pass',
                                'message': f'Using modern TLS version: {version}'
                            })
                        elif 'TLSv1.2' in version:
                            findings.append({
                                'status': 'warning',
                                'message': f'Using TLS version: {version} (consider upgrading to TLS 1.3)'
                            })
                        else:
                            findings.append({
                                'status': 'fail',
                                'message': f'Using outdated TLS version: {version}'
                            })
                        
                        # Check cipher strength
                        if cipher:
                            cipher_name = cipher[0]
                            if 'AES' in cipher_name and '256' in cipher_name:
                                findings.append({
                                    'status': 'pass',
                                    'message': f'Strong cipher suite: {cipher_name}'
                                })
                            elif 'AES' in cipher_name:
                                findings.append({
                                    'status': 'warning',
                                    'message': f'Moderate cipher suite: {cipher_name}'
                                })
                            else:
                                findings.append({
                                    'status': 'fail',
                                    'message': f'Weak cipher suite: {cipher_name}'
                                })
                        
                        # Check certificate details
                        if cert:
                            # Check key size
                            if 'subjectAltName' in cert:
                                findings.append({
                                    'status': 'pass',
                                    'message': 'Certificate includes Subject Alternative Names (SAN)'
                                })
                            
                            # Check certificate transparency
                            if 'ct_precert_scts' in cert or 'ct_cert_scts' in cert:
                                findings.append({
                                    'status': 'pass',
                                    'message': 'Certificate Transparency logs present'
                                })
                            else:
                                findings.append({
                                    'status': 'warning',
                                    'message': 'Certificate Transparency logs not found'
                                })
                            
                            # Check certificate chain
                            try:
                                context.verify_mode = ssl.CERT_REQUIRED
                                context.check_hostname = True
                                with socket.create_connection((parsed_url.netloc, 443), timeout=10) as sock:
                                    with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                                        cert_chain = ssock.getpeercert()
                                        if cert_chain:
                                            findings.append({
                                                'status': 'pass',
                                                'message': 'Certificate chain validation successful'
                                            })
                            except:
                                findings.append({
                                    'status': 'fail',
                                    'message': 'Certificate chain validation failed'
                                })
                                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Advanced SSL analysis failed: {str(e)}'
            })
        
        return findings

    def check_malware_indicators(self, url, domain):
        """Check for malware and phishing indicators"""
        findings = []
        
        try:
            # Check for suspicious URL patterns
            for pattern in self.malicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    findings.append({
                        'status': 'fail',
                        'message': f'URL contains suspicious pattern: {pattern}'
                    })
                    break
            
            # Check for IP-based domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                findings.append({
                    'status': 'fail',
                    'message': 'Domain is an IP address - potential security risk'
                })
            
            # Check for excessive subdomains (potential phishing)
            subdomain_count = len(domain.split('.')) - 2
            if subdomain_count > 3:
                findings.append({
                    'status': 'warning',
                    'message': f'Excessive subdomains ({subdomain_count}) - potential phishing attempt'
                })
            
            # Check for homograph attacks (similar looking characters)
            suspicious_chars = ['xn--', '0', '1', 'l', 'I']
            for char in suspicious_chars:
                if char in domain:
                    findings.append({
                        'status': 'warning',
                        'message': f'Domain contains potentially suspicious characters: {char}'
                    })
            
            # Check for brand impersonation
            brand_keywords = ['paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft', 'netflix']
            domain_lower = domain.lower()
            for brand in brand_keywords:
                if brand in domain_lower and not domain_lower.endswith(f'.{brand}.com'):
                    findings.append({
                        'status': 'fail',
                        'message': f'Potential brand impersonation detected: {brand}'
                    })
            
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                findings.append({
                    'status': 'fail',
                    'message': f'Domain uses suspicious TLD: {domain}'
                })
            
            # Check for excessive numbers in domain
            number_count = sum(c.isdigit() for c in domain)
            if number_count > 3:
                findings.append({
                    'status': 'warning',
                    'message': f'Domain contains many numbers ({number_count}) - potential suspicious'
                })
                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Malware detection failed: {str(e)}'
            })
        
        return findings

    def check_port_security(self, domain):
        """Check for open ports and potential vulnerabilities"""
        findings = []
        
        try:
            # Quick port scan for common ports
            open_ports = []
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    return port if result == 0 else None
                except:
                    return None
            
            # Scan ports in parallel
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {executor.submit(scan_port, port): port for port in self.common_ports}
                for future in as_completed(future_to_port, timeout=10):
                    port = future.result()
                    if port:
                        open_ports.append(port)
            
            # Analyze open ports
            if not open_ports:
                findings.append({
                    'status': 'pass',
                    'message': 'No common vulnerable ports detected'
                })
            else:
                dangerous_ports = [21, 23, 25, 110, 143, 3306, 3389, 5432]
                for port in open_ports:
                    if port in dangerous_ports:
                        findings.append({
                            'status': 'fail',
                            'message': f'Dangerous port {port} is open (FTP/Telnet/SMTP/POP3/IMAP/MySQL/RDP/PostgreSQL)'
                        })
                    elif port in [80, 443]:
                        findings.append({
                            'status': 'pass',
                            'message': f'Standard web port {port} is open'
                        })
                    else:
                        findings.append({
                            'status': 'warning',
                            'message': f'Port {port} is open - verify if necessary'
                        })
                        
        except Exception as e:
            findings.append({
                'status': 'warning',
                'message': f'Port scanning failed: {str(e)}'
            })
        
        return findings

    def check_dns_security(self, domain):
        """Advanced DNS security checks"""
        findings = []
        
        if not DNS_AVAILABLE:
            findings.append({
                'status': 'warning',
                'message': 'DNS library not available - DNS security checks skipped'
            })
            return findings
        
        try:
            # Check for DNSSEC
            try:
                dns.resolver.resolve(domain, 'DNSKEY')
                findings.append({
                    'status': 'pass',
                    'message': 'DNSSEC is enabled'
                })
            except:
                findings.append({
                    'status': 'warning',
                    'message': 'DNSSEC not found - DNS responses may not be authenticated'
                })
            
            # Check for CAA records
            try:
                dns.resolver.resolve(domain, 'CAA')
                findings.append({
                    'status': 'pass',
                    'message': 'CAA records present - certificate authority restrictions configured'
                })
            except:
                findings.append({
                    'status': 'warning',
                    'message': 'CAA records not found - no certificate authority restrictions'
                })
            
            # Check for DMARC
            try:
                dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                findings.append({
                    'status': 'pass',
                    'message': 'DMARC record found'
                })
            except:
                findings.append({
                    'status': 'warning',
                    'message': 'DMARC record not found - email authentication not configured'
                })
            
            # Check for subdomain enumeration
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging']
            found_subdomains = []
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f'{subdomain}.{domain}'
                    dns.resolver.resolve(full_domain, 'A')
                    found_subdomains.append(subdomain)
                except:
                    continue
            
            if found_subdomains:
                findings.append({
                    'status': 'info',
                    'message': f'Found subdomains: {", ".join(found_subdomains)}'
                })
            
            # Check for DNS wildcards
            try:
                random_subdomain = f'random{int(time.time())}.{domain}'
                dns.resolver.resolve(random_subdomain, 'A')
                findings.append({
                    'status': 'warning',
                    'message': 'DNS wildcard detected - potential security risk'
                })
            except:
                pass
                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'DNS security check failed: {str(e)}'
            })
        
        return findings

    def check_email_security(self, domain):
        """Check email security records"""
        findings = []
        
        if not DNS_AVAILABLE:
            findings.append({
                'status': 'warning',
                'message': 'DNS library not available - email security checks skipped'
            })
            return findings
        
        try:
            # Check SPF record
            try:
                spf_records = dns.resolver.resolve(domain, 'TXT')
                spf_found = False
                for record in spf_records:
                    if 'v=spf1' in str(record):
                        spf_found = True
                        spf_content = str(record)
                        if 'all' in spf_content and '~all' not in spf_content and '-all' not in spf_content:
                            findings.append({
                                'status': 'warning',
                                'message': 'SPF record found but not strict (uses ?all instead of -all)'
                            })
                        else:
                            findings.append({
                                'status': 'pass',
                                'message': 'SPF record found and properly configured'
                            })
                        break
                
                if not spf_found:
                    findings.append({
                        'status': 'fail',
                        'message': 'SPF record not found - email spoofing protection missing'
                    })
            except:
                findings.append({
                    'status': 'fail',
                    'message': 'SPF record not found'
                })
            
            # Check DKIM
            try:
                dkim_records = dns.resolver.resolve(f'default._domainkey.{domain}', 'TXT')
                findings.append({
                    'status': 'pass',
                    'message': 'DKIM record found'
                })
            except:
                findings.append({
                    'status': 'warning',
                    'message': 'DKIM record not found - email authentication incomplete'
                })
            
            # Check DMARC
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_found = False
                for record in dmarc_records:
                    if 'v=DMARC1' in str(record):
                        dmarc_found = True
                        dmarc_content = str(record)
                        if 'p=reject' in dmarc_content:
                            findings.append({
                                'status': 'pass',
                                'message': 'DMARC configured with reject policy'
                            })
                        elif 'p=quarantine' in dmarc_content:
                            findings.append({
                                'status': 'warning',
                                'message': 'DMARC configured with quarantine policy'
                            })
                        else:
                            findings.append({
                                'status': 'warning',
                                'message': 'DMARC configured with monitor policy only'
                            })
                        break
                
                if not dmarc_found:
                    findings.append({
                        'status': 'fail',
                        'message': 'DMARC record not found'
                    })
            except:
                findings.append({
                    'status': 'fail',
                    'message': 'DMARC record not found'
                })
                
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Email security check failed: {str(e)}'
            })
        
        return findings

    def check_webapp_security(self, url):
        """Check web application security"""
        findings = []
        
        try:
            # Check for common security headers
            response = requests.get(url, headers=self.headers, timeout=10, allow_redirects=True)
            
            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header:
                findings.append({
                    'status': 'warning',
                    'message': f'Server information disclosed: {server_header}'
                })
            
            # Check for X-Powered-By header
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                findings.append({
                    'status': 'fail',
                    'message': f'Technology stack exposed: {powered_by}'
                })
            
            # Check for directory listing
            if 'Index of' in response.text or 'Directory listing' in response.text:
                findings.append({
                    'status': 'fail',
                    'message': 'Directory listing enabled - information disclosure risk'
                })
            
            # Check for error messages in response
            error_indicators = ['error', 'exception', 'stack trace', 'debug', 'warning']
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    findings.append({
                        'status': 'warning',
                        'message': f'Potential error information disclosure: {indicator}'
                    })
                    break
            
            # Check for robots.txt
            try:
                robots_response = requests.get(f"{url.rstrip('/')}/robots.txt", timeout=5)
                if robots_response.status_code == 200:
                    findings.append({
                        'status': 'info',
                        'message': 'robots.txt file found'
                    })
            except:
                pass
            
            # Check for security.txt
            try:
                security_response = requests.get(f"{url.rstrip('/')}/.well-known/security.txt", timeout=5)
                if security_response.status_code == 200:
                    findings.append({
                        'status': 'pass',
                        'message': 'security.txt file found - good security practice'
                    })
            except:
                findings.append({
                    'status': 'info',
                    'message': 'security.txt file not found - consider adding one'
                })
            
            # Check for common vulnerabilities
            vulnerable_paths = [
                '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
                '/config', '/backup', '/test', '/debug', '/api', '/swagger'
            ]
            
            for path in vulnerable_paths:
                try:
                    test_response = requests.get(f"{url.rstrip('/')}{path}", timeout=3)
                    if test_response.status_code in [200, 301, 302]:
                        findings.append({
                            'status': 'warning',
                            'message': f'Potentially sensitive path accessible: {path}'
                        })
                except:
                    continue
                    
        except Exception as e:
            findings.append({
                'status': 'fail',
                'message': f'Web application security check failed: {str(e)}'
            })
        
        return findings

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
                    elif 'Malware' in category:
                        recommendations.append('Investigate potential security threats immediately')
                    elif 'Port' in category:
                        recommendations.append('Close unnecessary ports and secure open ones')
                    elif 'Email' in category:
                        recommendations.append('Implement proper email authentication (SPF, DKIM, DMARC)')
                    elif 'Web App' in category:
                        recommendations.append('Review and secure web application configuration')
                elif finding['status'] == 'warning':
                    if 'SSL' in finding.get('message', ''):
                        recommendations.append('Renew SSL certificate before expiration')
                    elif 'HSTS' in finding.get('message', ''):
                        recommendations.append('Implement HSTS header for better security')
                    elif 'Domain' in category and 'new' in finding.get('message', ''):
                        recommendations.append('Exercise caution with newly registered domains')
                    elif 'TLS' in finding.get('message', ''):
                        recommendations.append('Upgrade to TLS 1.3 for better security')
                    elif 'DNS' in category:
                        recommendations.append('Enable DNSSEC for DNS security')
                    elif 'Email' in category:
                        recommendations.append('Strengthen email security policies')
        
        # Remove duplicates and limit to top recommendations
        unique_recommendations = list(set(recommendations))
        return unique_recommendations[:8]  # Return top 8 recommendations 