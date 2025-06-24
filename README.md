# 🔒 SecureLink Chatbot

A Streamlit-based chatbot that analyzes website security and provides detailed insights in a conversational format.

## 🏗️ Project Overview

**SecureLink Chatbot** is an intelligent web application that:

- ✅ Accepts website URLs through a clean chat interface
- 🔍 Performs comprehensive security analysis
- 📊 Provides detailed findings with color-coded results
- 💡 Offers actionable recommendations
- 🚀 Deployed on Google Cloud Run for scalability

## 🔍 Security Analysis Features

The chatbot analyzes websites for:

### HTTPS & SSL Security
- HTTPS protocol usage
- SSL certificate validity and expiration
- Certificate issuer verification

### Domain Analysis
- Domain age and registration details
- Suspicious TLD detection (.tk, .ml, .ga, etc.)
- Phishing keyword detection
- IP address domain validation

### Network Security
- DNS resolution verification
- Private IP address detection
- DNS record analysis (SPF, TXT records)

### Content Security
- Security-related content detection
- Form presence analysis
- Website accessibility checks

### Security Headers
- HSTS (HTTP Strict Transport Security)
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options (MIME sniffing protection)
- Content Security Policy (CSP)

## 📁 Project Structure

```
securelink-chatbot/
├── app.py                  # Streamlit chatbot UI
├── checker.py              # Security check logic
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container definition
└── README.md               # Documentation
```

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd securelink-chatbot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:8501`

### Docker Local Testing

1. **Build the Docker image**
   ```bash
   docker build -t securelink-chatbot .
   ```

2. **Run the container**
   ```bash
   docker run -p 8080:8080 securelink-chatbot
   ```

3. **Access the application**
   Navigate to `http://localhost:8080`

## ☁️ Deployment to Google Cloud Run

### Prerequisites

1. **Google Cloud SDK** installed and configured
2. **Docker** installed
3. **Google Cloud Project** with billing enabled

### Step-by-Step Deployment

1. **Set your project ID**
   ```bash
   export PROJECT_ID="your-project-id"
   gcloud config set project $PROJECT_ID
   ```

2. **Enable required APIs**
   ```bash
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable run.googleapis.com
   ```

3. **Build and deploy to Cloud Run**
   ```bash
   # Build and push the container
   gcloud builds submit --tag gcr.io/$PROJECT_ID/securelink-chatbot
   
   # Deploy to Cloud Run
   gcloud run deploy securelink-chatbot \
     --image gcr.io/$PROJECT_ID/securelink-chatbot \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated \
     --port 8080 \
     --memory 1Gi \
     --cpu 1 \
     --max-instances 10
   ```

4. **Access your deployed application**
   The deployment will provide a URL like:
   `https://securelink-chatbot-xxxxx-uc.a.run.app`

### Advanced Deployment Options

#### Custom Domain Setup
```bash
# Map custom domain
gcloud run domain-mappings create \
  --service securelink-chatbot \
  --domain your-domain.com \
  --region us-central1
```

#### Environment Variables
```bash
gcloud run services update securelink-chatbot \
  --set-env-vars "ENV=production" \
  --region us-central1
```

#### Scaling Configuration
```bash
gcloud run services update securelink-chatbot \
  --min-instances 0 \
  --max-instances 20 \
  --cpu 2 \
  --memory 2Gi \
  --region us-central1
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STREAMLIT_SERVER_PORT` | Port for Streamlit server | `8080` |
| `STREAMLIT_SERVER_ADDRESS` | Server address | `0.0.0.0` |
| `ENV` | Environment (dev/prod) | `dev` |

### Customization

#### Adding New Security Checks

1. **Extend the SecurityChecker class** in `checker.py`
2. **Add new check method** following the existing pattern
3. **Update the analyze_url method** to include your new check
4. **Add corresponding UI elements** in `app.py`

#### Modifying UI Styling

Edit the CSS in the `app.py` file within the `<style>` tags to customize:
- Chat message appearance
- Color schemes
- Button styling
- Layout modifications

## 📊 Usage Examples

### Example 1: Secure Website
```
Input: https://google.com
Output: 
🟢 Overall Security Score: 95/100 (Secure)
✅ HTTPS is properly configured
✅ SSL certificate is valid and expires in 89 days
✅ Domain is 8,765 days old (established)
✅ Domain resolves to IP addresses: 142.250.190.78
✅ HSTS header present - enforces HTTPS
```

### Example 2: Suspicious Website
```
Input: http://suspicious-site.tk
Output:
🔴 Overall Security Score: 35/100 (High Risk)
❌ Website does not use HTTPS - data transmission is not encrypted
⚠️ Domain uses suspicious TLD: suspicious-site.tk
⚠️ Domain is very new (15 days old) - potential risk
⚠️ HSTS header missing - should enforce HTTPS
```

## 🛡️ Security Considerations

### Rate Limiting
- Consider implementing rate limiting for production use
- Monitor API usage and implement quotas

### Data Privacy
- The application does not store user data permanently
- All analysis is performed in real-time
- No personal information is collected

### Network Security
- Use HTTPS in production
- Implement proper CORS policies
- Consider adding authentication for sensitive deployments

## 🐛 Troubleshooting

### Common Issues

1. **WHOIS/DNS libraries not available**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - The application will gracefully handle missing optional libraries

2. **SSL certificate validation errors**
   - Some websites may have self-signed certificates
   - The application will report these as warnings

3. **Timeout errors**
   - Slow websites may cause timeouts
   - Consider increasing timeout values in the code

4. **Cloud Run deployment issues**
   - Ensure the container builds successfully locally first
   - Check that port 8080 is properly exposed
   - Verify billing is enabled on your GCP project

### Debug Mode

Enable debug logging by setting:
```bash
export STREAMLIT_LOGGER_LEVEL=debug
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Streamlit for the amazing web framework
- Python security community for best practices
- Google Cloud Platform for hosting infrastructure

---

**🔒 SecureLink Chatbot** - Making web security analysis accessible and conversational! # Streamlit-Security-Bot
