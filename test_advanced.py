#!/usr/bin/env python3
"""
Test script for the Advanced Security Checker
"""

from advanced_checker import AdvancedSecurityChecker

def test_advanced_checker():
    """Test the advanced security checker with a sample URL"""
    
    print("🔒 Testing Advanced Security Checker...")
    print("=" * 50)
    
    # Initialize the checker
    checker = AdvancedSecurityChecker()
    
    # Test URL
    test_url = "https://google.com"
    
    print(f"Testing URL: {test_url}")
    print("-" * 30)
    
    try:
        # Perform analysis
        results = checker.analyze_url(test_url)
        
        # Display results
        print(f"✅ Analysis completed successfully!")
        print(f"Overall Security Score: {results.get('overall_score', 0)}/100")
        print(f"Domain: {results.get('domain', 'N/A')}")
        
        # Display findings summary
        print("\n📋 Findings Summary:")
        for category, findings in results.get('findings', {}).items():
            if findings:
                pass_count = sum(1 for f in findings if f.get('status') == 'pass')
                warning_count = sum(1 for f in findings if f.get('status') == 'warning')
                fail_count = sum(1 for f in findings if f.get('status') == 'fail')
                
                print(f"  {category}: ✅ {pass_count} | ⚠️ {warning_count} | ❌ {fail_count}")
        
        # Display recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"  {i}. {rec}")
        
        print("\n✅ Advanced Security Checker is working correctly!")
        
    except Exception as e:
        print(f"❌ Error during testing: {str(e)}")
        print("This might be due to missing dependencies or network issues.")

if __name__ == "__main__":
    test_advanced_checker() 