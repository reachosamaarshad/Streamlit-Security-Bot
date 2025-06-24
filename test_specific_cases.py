#!/usr/bin/env python3
"""
Test script for the specific user cases
"""

import re

def extract_url_from_text(text):
    """Extract URL from text that might contain other words"""
    # More comprehensive URL pattern that handles various URL formats
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

def is_analysis_request(text):
    """Check if the user is requesting security analysis"""
    analysis_keywords = [
        'analyze', 'analysis', 'check', 'scan', 'security', 'secure', 'safe',
        'test', 'examine', 'inspect', 'review', 'audit', 'verify', 'validate',
        'assess', 'evaluate', 'investigate', 'look into', 'check out', 'please'
    ]
    
    text_lower = text.lower()
    
    # Check if text contains a URL
    has_url = extract_url_from_text(text) is not None
    
    # Check if text contains analysis keywords
    has_analysis_keywords = any(keyword in text_lower for keyword in analysis_keywords)
    
    # Check for direct URL input (just a URL)
    is_direct_url = bool(re.match(r'^https?://', text.strip()))
    
    # Also check for URLs without protocol (add https:// if needed)
    if not has_url and not is_direct_url:
        # Look for domain-like patterns
        potential_domains = extract_domain_from_text(text)
        if potential_domains:
            # If we find a domain and analysis keywords, treat as analysis request
            return has_analysis_keywords
    
    return has_url or has_analysis_keywords or is_direct_url

def test_specific_cases():
    """Test the specific cases mentioned by the user"""
    
    test_cases = [
        "now analyze this https://yaytext.com/bold-italic/",
        "can you please analyze this https://osama.shareresume.online/"
    ]
    
    print("🔍 Testing Specific User Cases")
    print("=" * 50)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: '{test_case}'")
        
        # Check if it's an analysis request
        is_analysis = is_analysis_request(test_case)
        print(f"   Analysis request: {is_analysis}")
        
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
        
        # Simulate the chatbot response logic
        if is_analysis:
            if url:
                print(f"   🎯 Would analyze: {url}")
            else:
                domain = extract_domain_from_text(test_case)
                if domain:
                    full_url = f"https://{domain}"
                    print(f"   🎯 Would analyze: {full_url}")
                else:
                    print(f"   ❌ No URL to analyze")
        else:
            print(f"   ❌ Not recognized as analysis request")
    
    print("\n" + "=" * 50)
    print("✅ Specific case testing completed!")

if __name__ == "__main__":
    test_specific_cases() 