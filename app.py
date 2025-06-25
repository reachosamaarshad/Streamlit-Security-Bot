import streamlit as st
import time
from datetime import datetime
from advanced_checker import AdvancedSecurityChecker
import re

# Page configuration
st.set_page_config(
    page_title="SecureLink Chatbot",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for chat-like interface
st.markdown("""
<style>
    /* Dark mode compatible chat interface */
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        display: flex;
        flex-direction: column;
        color: var(--text-color);
    }
    .user-message {
        background-color: rgba(33, 150, 243, 0.1);
        border-left: 4px solid #2196f3;
        color: var(--text-color);
    }
    .bot-message {
        background-color: rgba(156, 39, 176, 0.1);
        border-left: 4px solid #9c27b0;
        color: var(--text-color);
    }
    .security-issue {
        background-color: rgba(244, 67, 54, 0.1);
        border-left: 4px solid #f44336;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
        color: var(--text-color);
    }
    .security-pass {
        background-color: rgba(76, 175, 80, 0.1);
        border-left: 4px solid #4caf50;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
        color: var(--text-color);
    }
    .security-warning {
        background-color: rgba(255, 152, 0, 0.1);
        border-left: 4px solid #ff9800;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 0.25rem;
        color: var(--text-color);
    }
    
    /* Dark mode compatible text input */
    .stTextInput > div > div > input {
        border-radius: 25px;
        border: 2px solid var(--border-color);
        padding: 12px 20px;
        font-size: 16px;
        background-color: var(--background-color);
        color: var(--text-color);
    }
    .stTextInput > div > div > input:focus {
        border-color: #2196f3;
        box-shadow: 0 0 0 2px rgba(33, 150, 243, 0.2);
    }
    
    /* Dark mode compatible button */
    .stButton > button {
        border-radius: 25px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 24px;
        font-weight: 600;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        transition: all 0.3s ease;
        height: 48px;
        min-width: 80px;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        transform: translateY(-2px);
    }
    .stButton > button:active {
        transform: translateY(0);
        box-shadow: 0 2px 10px rgba(102, 126, 234, 0.4);
    }
    
    /* Fix alignment between text input and button */
    .row-widget.stHorizontal {
        align-items: end;
    }
    .stTextInput {
        margin-bottom: 0;
    }
    .stButton {
        margin-bottom: 0;
    }
    
    /* Dark mode compatible status cards */
    .status-card {
        background-color: var(--background-color);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
        color: var(--text-color);
    }
    
    /* Dark mode compatible security result cards */
    .security-result-card {
        background-color: var(--background-color);
        border: 1px solid var(--border-color);
        border-radius: 0.25rem;
        padding: 0.5rem;
        margin: 0.25rem 0;
        color: var(--text-color);
    }
    
    /* Ensure proper text contrast in dark mode */
    .chat-message strong {
        color: var(--text-color);
    }
    
    .chat-message small {
        color: var(--text-color);
        opacity: 0.7;
    }
    
    /* Dark mode compatible dividers */
    .divider {
        border-top: 1px solid var(--border-color);
        margin: 1rem 0;
    }
    
    /* Dark mode compatible header */
    .header-text {
        color: var(--text-color);
    }
    
    .header-subtitle {
        color: var(--text-color);
        opacity: 0.8;
    }
    
    /* Dark mode compatible footer */
    .footer-text {
        color: var(--text-color);
        opacity: 0.7;
    }
    
    /* Dark mode compatible sidebar */
    .sidebar-content {
        color: var(--text-color);
    }
    
    /* Ensure proper contrast for all text elements */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-color);
    }
    
    p {
        color: var(--text-color);
    }
    
    /* Dark mode compatible list items */
    ul, ol {
        color: var(--text-color);
    }
    
    li {
        color: var(--text-color);
    }
    
    /* Streamlit dark mode specific overrides */
    [data-testid="stSidebar"] {
        background-color: var(--background-color);
    }
    
    [data-testid="stSidebar"] .sidebar-content {
        color: var(--text-color);
    }
    
    /* Ensure proper contrast for Streamlit elements */
    .stMarkdown {
        color: var(--text-color);
    }
    
    .stMarkdown p {
        color: var(--text-color);
    }
    
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, 
    .stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
        color: var(--text-color);
    }
    
    /* Fix for Streamlit's default styling conflicts */
    .main .block-container {
        color: var(--text-color);
    }
    
    /* Ensure proper visibility of all text in both themes */
    .stMarkdown, .stMarkdown * {
        color: inherit;
    }
    
    /* Override any hardcoded colors that might interfere */
    .stMarkdown [style*="color: #666"] {
        color: var(--text-color) !important;
        opacity: 0.7;
    }
    
    .stMarkdown [style*="color: #"] {
        color: var(--text-color) !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for chat history
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Initialize security checker
@st.cache_resource
def get_security_checker():
    return AdvancedSecurityChecker()

security_checker = get_security_checker()

# Header
st.markdown("""
<div style="text-align: center; padding: 2rem 0;">
    <h1 class="header-text">🔒 SecureLink Chatbot</h1>
    <p class="header-subtitle" style="font-size: 1.2rem;">Hi! I'm your website security assistant. Ask me to analyze any website! 🔍</p>
</div>
""", unsafe_allow_html=True)

# URL validation function
def is_valid_url(url):
    """Basic URL validation"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None

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
    is_direct_url = is_valid_url(text.strip())
    
    # Also check for URLs without protocol (add https:// if needed)
    if not has_url and not is_direct_url:
        # Look for domain-like patterns
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
        )
        potential_domains = domain_pattern.findall(text)
        if potential_domains:
            # If we find a domain and analysis keywords, treat as analysis request
            return has_analysis_keywords
    
    return has_url or has_analysis_keywords or is_direct_url

def format_security_results(results):
    """Format security analysis results for chat display"""
    # Create a container for the results
    result_container = st.container()
    
    with result_container:
        st.markdown(f"### 🔍 Security Analysis Results for: {results['url']}")
        
        # Overall score
        score = results.get('overall_score', 0)
        if score >= 80:
            status_emoji = "🟢"
            status_text = "Secure"
            status_color = "green"
        elif score >= 60:
            status_emoji = "🟡"
            status_text = "Moderate Risk"
            status_color = "orange"
        else:
            status_emoji = "🔴"
            status_text = "High Risk"
            status_color = "red"
        
        # Display overall score
        st.markdown(f"""
        <div class="status-card" style="border-left: 4px solid {status_color};">
            <h5>{status_emoji} Overall Security Score: {score}/100 ({status_text})</h5>
        </div>
        """, unsafe_allow_html=True)
        
        # Detailed findings
        st.markdown("### 📋 Detailed Findings:")
        
        for category, details in results.get('findings', {}).items():
            if details:
                st.markdown(f"**🔹 {category}:**")
                
                for finding in details:
                    status = finding.get('status', '')
                    message = finding.get('message', '')
                    
                    if status == 'pass':
                        st.markdown(f"""
                        <div class="security-result-card" style="border-left: 4px solid #4caf50;">
                            ✅ {message}
                        </div>
                        """, unsafe_allow_html=True)
                    elif status == 'warning':
                        st.markdown(f"""
                        <div class="security-result-card" style="border-left: 4px solid #ff9800;">
                            ⚠️ {message}
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="security-result-card" style="border-left: 4px solid #f44336;">
                            ❌ {message}
                        </div>
                        """, unsafe_allow_html=True)
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            st.markdown("### 💡 Recommendations:")
            for rec in recommendations:
                st.markdown(f"• {rec}")
    
    # Create a detailed chat response
    chat_response = f"🔍 Security Analysis Complete for: {results['url']}\n\n"
    chat_response += f"**Overall Score:** {score}/100 ({status_text})\n\n"
    
    # Collect findings for chat response
    passed_items = []
    warning_items = []
    failed_items = []
    
    for category, details in results.get('findings', {}).items():
        for finding in details:
            status = finding.get('status', '')
            message = finding.get('message', '')
            
            if status == 'pass':
                passed_items.append(message)
            elif status == 'warning':
                warning_items.append(message)
            else:
                failed_items.append(message)
    
    # Build conversational response
    if passed_items:
        chat_response += "✅ **What's Working Well:**\n"
        for item in passed_items[:3]:  # Show top 3 passed items
            chat_response += f"• {item}\n"
        chat_response += "\n"
    
    if warning_items:
        chat_response += "⚠️ **Areas of Concern:**\n"
        for item in warning_items[:3]:  # Show top 3 warnings
            chat_response += f"• {item}\n"
        chat_response += "\n"
    
    if failed_items:
        chat_response += "❌ **Critical Issues Found:**\n"
        for item in failed_items[:3]:  # Show top 3 failures
            chat_response += f"• {item}\n"
        chat_response += "\n"
    
    # Add recommendations if any
    if recommendations:
        chat_response += "💡 **My Recommendations:**\n"
        for rec in recommendations[:2]:  # Show top 2 recommendations
            chat_response += f"• {rec}\n"
        chat_response += "\n"
    
    chat_response += "Check the detailed results above for a complete security assessment! 🔒"
    
    return chat_response

def get_chatbot_response(user_input):
    """Generate appropriate chatbot response based on user input"""
    user_input_lower = user_input.lower().strip()
    
    # Greeting responses
    greetings = {
        'hello': "Hello! 👋 I'm your website security assistant. How can I help you today?",
        'hi': "Hi there! 😊 I'm here to help you analyze website security. What would you like to check?",
        'hey': "Hey! 👋 Ready to analyze some websites for security? Just let me know what you'd like to check!",
        'good morning': "Good morning! ☀️ I'm your security assistant. How can I help you today?",
        'good afternoon': "Good afternoon! 🌤️ I'm here to help with website security analysis!",
        'good evening': "Good evening! 🌙 Ready to check some website security?",
        'how are you': "I'm doing great, thanks for asking! 😊 I'm ready to help you analyze website security. What would you like to check?",
        'how are you doing': "I'm doing well, thank you! 😊 I'm here to help you with website security analysis. What can I assist you with?",
        'what\'s up': "Not much, just ready to analyze some websites! 🔍 What would you like me to check for you?",
        'sup': "Hey! 👋 Ready to dive into some website security analysis? What's on your mind?"
    }
    
    # Check for greetings
    for greeting, response in greetings.items():
        if greeting in user_input_lower:
            return response
    
    # Check if it's an analysis request
    if is_analysis_request(user_input):
        # First try to extract URL with protocol
        url = extract_url_from_text(user_input)
        
        # If no URL found, try to extract domain and add protocol
        if not url:
            domain_pattern = re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
            )
            domains = domain_pattern.findall(user_input)
            if domains:
                # Take the first domain found and add https://
                url = f"https://{domains[0]}"
        
        if not url:
            # If no URL found but analysis keywords present, ask for URL
            return "I'd be happy to analyze a website for you! 🔍 Please provide the URL you'd like me to check for security issues."
        
        # Validate URL
        if not is_valid_url(url):
            return "I see you want me to analyze a website, but that doesn't look like a valid URL. Could you please provide a proper website address (like https://example.com)?"
        
        # Perform analysis
        try:
            with st.spinner("🔍 Analyzing website security..."):
                results = security_checker.analyze_url(url)
                return format_security_results(results)
        except Exception as e:
            return f"❌ Sorry, I encountered an error while analyzing {url}: {str(e)}"
    
    # Default response for non-analysis requests
    friendly_responses = [
        "I'm here to help you analyze website security! 🔍 Just ask me to check any website URL and I'll give you a detailed security report.",
        "I'd love to help! I'm a website security assistant. You can ask me to analyze any website by providing its URL.",
        "That's interesting! I'm specifically designed to analyze website security. Try asking me something like 'Can you analyze https://example.com?' or 'Check the security of google.com'",
        "I'm your security assistant! 🔒 I can analyze websites for security issues. Just provide me with a URL and ask me to check it.",
        "I'm here to help with website security analysis! Try asking me to analyze a specific website URL.",
        "I'm a website security chatbot! 🔍 I can check websites for security vulnerabilities, SSL certificates, and more. Just give me a URL to analyze!"
    ]
    
    import random
    return random.choice(friendly_responses)

# Display chat history
for message in st.session_state.messages:
    with st.container():
        if message["role"] == "user":
            st.markdown(f"""
            <div class="chat-message user-message">
                <strong>You:</strong> {message["content"]}
                <small style="color: #666;">{message["timestamp"]}</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="chat-message bot-message">
                <strong>SecureLink Bot:</strong>
                {message["content"]}
                <small style="color: #666;">{message["timestamp"]}</small>
            </div>
            """, unsafe_allow_html=True)

# Input section
st.markdown("---")

# Create a form for Enter key functionality
with st.form(key="chat_form", clear_on_submit=True):
    col1, col2 = st.columns([4, 1])
    
    with col1:
        user_input = st.text_input(
            "Type your message here...",
            placeholder="Hello! or analyze https://example.com",
            key="user_input",
            label_visibility="collapsed"
        )
    
    with col2:
        send_button = st.form_submit_button(
            "Send",
            use_container_width=True,
            type="primary"
        )

# Process user input (both button click and Enter key)
if send_button and user_input:
    if not user_input.strip():
        st.error("Please enter a message")
    else:
        # Add user message to chat
        user_message = {
            "role": "user",
            "content": user_input.strip(),
            "timestamp": datetime.now().strftime("%H:%M")
        }
        st.session_state.messages.append(user_message)
        
        # Get bot response
        bot_response = get_chatbot_response(user_input.strip())
        
        # Add bot message to chat
        bot_message = {
            "role": "assistant",
            "content": bot_response,
            "timestamp": datetime.now().strftime("%H:%M")
        }
        st.session_state.messages.append(bot_message)
        
        # Rerun to display new messages
        st.rerun()

# Sidebar with additional info
with st.sidebar:
    st.markdown("### 🎨 Theme")
    st.markdown("""
    <div class="sidebar-content">
    The app automatically adapts to your browser's theme preference. 
    If you're having visibility issues, try switching your browser's theme.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### ℹ️ About Me")
    st.markdown("""
    <div class="sidebar-content">
    I'm your advanced website security assistant! 🔒
    
    I can analyze websites for:
    • HTTPS/SSL certificate validity
    • Advanced TLS/SSL analysis
    • Malware & phishing detection
    • Port security & vulnerability scanning
    • DNS security & configuration
    • Email security (SPF, DKIM, DMARC)
    • Web application security
    • Domain age & registration
    • Network security analysis
    • Content security assessment
    
    Just ask me to analyze any website URL!
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 💬 How to Use")
    st.markdown("""
    <div class="sidebar-content">
    **Greetings:** Say hello, hi, how are you, etc.
    
    **Analysis:** Ask me to analyze any website:
    • "Analyze https://example.com"
    • "Check the security of google.com"
    • "Can you please analyze this https://yaytext.com/bold-italic/"
    • "Now analyze this https://osama.shareresume.online/"
    • "Is facebook.com secure?"
    • "Scan this website: amazon.com"
    • "Please check yaytext.com"
    • "Security analysis for github.com"
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🔍 Advanced Features")
    st.markdown("""
    <div class="sidebar-content">
    **Smart URL Detection:**
    • Works with full URLs (https://example.com)
    • Works with domains only (example.com)
    • Handles URLs with paths and parameters
    • Natural language processing
    
    **Comprehensive Analysis:**
    • 10+ security categories
    • Real-time scoring (0-100)
    • Detailed recommendations
    • Threat detection
    </div>
    """, unsafe_allow_html=True)
    
    # Clear chat button
    if st.button("🗑️ Clear Chat"):
        st.session_state.messages = []
        st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 1rem;">
    <p class="footer-text">🔒 SecureLink Chatbot - Your friendly security assistant</p>
</div>
""", unsafe_allow_html=True) 