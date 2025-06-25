# �� SecureLink Chatbot - Advanced Website Security Analysis

A sophisticated Streamlit-based chatbot that provides comprehensive website security analysis with advanced threat detection capabilities.

## 🚀 Features

### Advanced Security Analysis
- **🔐 SSL/TLS Deep Analysis**: Certificate validation, cipher strength, TLS version detection
- **🛡️ Malware & Phishing Detection**: Pattern recognition, brand impersonation detection, suspicious URL analysis
- **🌐 DNS Security**: DNSSEC validation, CAA records, subdomain enumeration, DNS wildcard detection
- **📧 Email Security**: SPF, DKIM, DMARC record analysis and policy validation
- **🔍 Port Security**: Automated port scanning for common vulnerabilities
- **🌍 Network Security**: IP resolution, private IP detection, DNS record analysis
- **📋 Web Application Security**: Security headers, information disclosure, directory listing detection
- **🏷️ Domain Analysis**: WHOIS lookup, domain age verification, suspicious TLD detection
- **📊 Content Security**: Security policy analysis, form detection, error message analysis

### Chat Interface
- **💬 Natural Language Processing**: Intelligent conversation with LLM integration
- **🎯 Smart URL Detection**: Automatically extracts URLs from natural language
- **📈 Real-time Analysis**: Live security assessment with detailed scoring
- **🎨 Modern UI**: Beautiful, responsive chat interface with security-focused design

### LLM Integration
- **🤖 Multiple LLM Providers**: Support for DeepInfra, Hugging Face, Together AI, and Cursor API
- **🔄 Intelligent Fallback**: Automatic fallback to keyword matching if LLM unavailable
- **🔧 Configurable**: Easy API key management and provider switching

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup
```bash
# Clone the repository
git clone <your-repo-url>
cd chatbot_marc

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Environment Variables
Create a `.env` file with your API keys:
```env
DEEPINFRA_API_KEY=your_deepinfra_key_here
HUGGINGFACE_TOKEN=your_huggingface_token_here
TOGETHER_API_KEY=your_together_key_here
CURSOR_API_KEY=your_cursor_key_here
```

## 🚀 Usage

### Running the Application
```bash
# Activate virtual environment
source venv/bin/activate

# Run the Streamlit app
streamlit run app.py
```

The application will be available at `http://localhost:8501`

### Using the Chatbot
1. **Start a conversation**: The chatbot responds to greetings and general questions
2. **Request security analysis**: Ask to analyze any website URL
3. **Natural language**: Use phrases like "Can you check the security of google.com?" or "Analyze https://example.com"
4. **Get detailed results**: Receive comprehensive security assessment with scores and recommendations

## 🔍 Security Analysis Categories

### 1. HTTPS & SSL Analysis
- ✅ HTTPS protocol validation
- ✅ SSL certificate expiration check
- ✅ Certificate issuer verification
- ✅ Certificate chain validation

### 2. Advanced SSL/TLS Analysis
- ✅ TLS version detection (1.2, 1.3)
- ✅ Cipher suite strength assessment
- ✅ Certificate transparency logs
- ✅ Subject Alternative Names (SAN) validation

### 3. Malware & Phishing Detection
- ✅ Suspicious URL pattern recognition
- ✅ Brand impersonation detection
- ✅ Homograph attack detection
- ✅ Suspicious TLD identification
- ✅ Excessive subdomain analysis

### 4. Port Security
- ✅ Automated port scanning (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443)
- ✅ Dangerous port identification
- ✅ Service enumeration
- ✅ Vulnerability assessment

### 5. DNS Security
- ✅ DNSSEC validation
- ✅ CAA record analysis
- ✅ Subdomain enumeration
- ✅ DNS wildcard detection
- ✅ DNS record analysis

### 6. Email Security
- ✅ SPF record validation and policy analysis
- ✅ DKIM record detection
- ✅ DMARC policy assessment
- ✅ Email authentication completeness

### 7. Web Application Security
- ✅ Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- ✅ Information disclosure detection
- ✅ Directory listing identification
- ✅ Error message analysis
- ✅ Technology stack exposure detection

### 8. Domain Analysis
- ✅ WHOIS lookup and domain age verification
- ✅ Suspicious TLD detection
- ✅ Domain registration analysis
- ✅ IP-based domain detection

### 9. Network Security
- ✅ DNS resolution validation
- ✅ IP address analysis
- ✅ Private IP detection
- ✅ Network configuration assessment

### 10. Content Security
- ✅ Security-related content detection
- ✅ Form and data collection analysis
- ✅ Privacy policy identification
- ✅ Security indicator assessment

## 📊 Scoring System

The application provides a comprehensive security score (0-100) based on:

- **🟢 Pass (10 points)**: Security measure properly implemented
- **🟡 Warning (5 points)**: Security measure present but could be improved
- **🔴 Fail (0 points)**: Security measure missing or vulnerable

### Score Categories:
- **80-100**: Secure - Well-protected website
- **60-79**: Moderate Risk - Some security improvements needed
- **0-59**: High Risk - Immediate security attention required

## 🐳 Docker Deployment

### Build and Run with Docker
```bash
# Build the Docker image
docker build -t securelink-chatbot .

# Run the container
docker run -p 8501:8501 securelink-chatbot
```

### Deploy to Google Cloud Run
```bash
# Make deploy script executable
chmod +x deploy.sh

# Deploy to Cloud Run
./deploy.sh
```

## 🔧 Configuration

### LLM Provider Selection
The application automatically selects the best available LLM provider:
1. DeepInfra (recommended for performance)
2. Hugging Face (good for open models)
3. Together AI (alternative option)
4. Cursor API (if available)
5. Fallback to keyword matching

### Security Check Customization
You can modify the security checks by editing `advanced_checker.py`:
- Add new port numbers to scan
- Update suspicious patterns
- Modify security header requirements
- Customize scoring weights

## 🧪 Testing

### Test the Advanced Security Checker
```bash
# Run the test script
python test_advanced.py
```

This will test the security checker with a sample URL and display comprehensive results.

### Manual Testing
1. Start the application
2. Try different types of URLs (secure, suspicious, new domains)
3. Test various conversation patterns
4. Verify all security categories are working

## 📈 Performance

### Analysis Speed
- **Basic checks**: 2-5 seconds
- **Full analysis**: 10-30 seconds (depending on network and target)
- **Port scanning**: 5-15 seconds (parallel scanning)

### Resource Usage
- **Memory**: ~50-100MB
- **CPU**: Low usage during analysis
- **Network**: Moderate usage for external checks

## 🔒 Security Considerations

### Privacy
- No user data is stored permanently
- Analysis results are session-based
- No sensitive information is logged

### Rate Limiting
- Built-in delays between requests
- Respectful scanning practices
- Configurable timeouts

### Legal Compliance
- Only performs non-intrusive security checks
- Respects robots.txt and security policies
- Intended for legitimate security assessment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the documentation
2. Review existing issues
3. Create a new issue with detailed information

## 🔄 Updates

### Recent Enhancements
- ✅ Advanced SSL/TLS analysis
- ✅ Malware and phishing detection
- ✅ Comprehensive port scanning
- ✅ DNS security validation
- ✅ Email security analysis
- ✅ Web application security checks
- ✅ Enhanced scoring system
- ✅ Improved recommendations

### Planned Features
- 🔄 Real-time threat intelligence integration
- 🔄 Custom security policy templates
- 🔄 Automated security report generation
- 🔄 API endpoint for external integrations
- 🔄 Mobile-responsive design improvements

---

**🔒 SecureLink Chatbot** - Your intelligent website security companion!
 