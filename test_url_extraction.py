#!/usr/bin/env python3
"""
Test script for URL extraction functionality
"""

import re

def extract_url_from_text(text):
    """Extract URL from text that might contain other words"""
    # More comprehensive URL pattern that handles various URL formats
    # This pattern matches URLs with protocols, domains, paths, and query parameters
    url_pattern = re.compile(
        r'https?://'  # http:// or https://
        r'(?:[-\w.])+(?:[:\d]+)?'  # domain and optional port
        r'(?:/(?:[\w/_.~!*\'();:@&=+$,%#-]|%[0-9a-fA-F]{2})*)*'  # path and query parameters
        r'(?:\?(?:[\w/_.~!*\'();:@&=+$,%#-]|%[0-9a-fA-F]{2})*)?'  # query string
        r'(?:#(?:[\w/_.~!*\'();:@&=+$,%#-]|%[0-9a-fA-F]{2})*)?',  # fragment
        re.IGNORECASE
    )
    
    urls = url_pattern.findall(text)
    return urls[0] if urls else None

def extract_domain_from_text(text):
    """Extract domain from text without protocol"""
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
    )
    domains = domain_pattern.findall(text)
    return domains[0] if domains else None

def test_url_extraction():
    """Test URL extraction with various message formats"""
    
    test_cases = [
        "now analyze this https://yaytext.com/bold-italic/",
        "can you please analyze this https://osama.shareresume.online/",
        "check the security of google.com",
        "analyze https://example.com/path?param=value",
        "is facebook.com secure?",
        "scan this website: amazon.com",
        "please check https://test.com",
        "can you analyze yaytext.com",
        "security check for https://github.com/user/repo",
        "test the security of https://stackoverflow.com/questions/123",
        "analyze this URL: https://medium.com/@user/article",
        "check https://reddit.com/r/programming",
        "security analysis for https://news.ycombinator.com/item?id=123",
        "please analyze https://example.com#section",
        "can you check the security of https://test.example.com:8080/path"
    ]
    
    print("🔍 Testing URL Extraction Functionality")
    print("=" * 50)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: '{test_case}'")
        
        # Try to extract URL with protocol
        url = extract_url_from_text(test_case)
        if url:
            print(f"   ✅ URL found: {url}")
        else:
            # Try to extract domain without protocol
            domain = extract_domain_from_text(test_case)
            if domain:
                full_url = f"https://{domain}"
                print(f"   ✅ Domain found: {domain} -> {full_url}")
            else:
                print(f"   ❌ No URL or domain found")
    
    print("\n" + "=" * 50)
    print("✅ URL extraction testing completed!")

if __name__ == "__main__":
    test_url_extraction() 