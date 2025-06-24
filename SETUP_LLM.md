# 🤖 LLM Integration Setup Guide

This guide will help you set up LLM integration for your SecureLink Chatbot.

## 🆓 Free LLM Options

### 1. **DeepInfra** (Recommended - Most Reliable)
- Visit: https://deepinfra.com/
- Sign up for free account
- Get your API key
- Set environment variable: `DEEPINFRA_API_KEY=your_key_here`

### 2. **Hugging Face**
- Visit: https://huggingface.co/
- Create account and get API token
- Set environment variable: `HUGGINGFACE_API_KEY=your_token_here`

### 3. **Together AI**
- Visit: https://together.ai/
- Sign up for free credits
- Get API key
- Set environment variable: `TOGETHER_API_KEY=your_key_here`

## 💰 Paid Options

### 4. **Cursor API** (If you have paid account)
- Check Cursor documentation for API access
- Set environment variable: `CURSOR_API_KEY=your_key_here`

## ⚙️ Configuration

### Option 1: Environment Variables
```bash
export DEEPINFRA_API_KEY="your_key_here"
export HUGGINGFACE_API_KEY="your_token_here"
export TOGETHER_API_KEY="your_key_here"
export CURSOR_API_KEY="your_key_here"
```

### Option 2: .env File
Create a `.env` file in your project root:
```env
DEEPINFRA_API_KEY=your_key_here
HUGGINGFACE_API_KEY=your_token_here
TOGETHER_API_KEY=your_key_here
CURSOR_API_KEY=your_key_here
```

### Option 3: Direct in config.py
Edit `config.py` and add your keys directly:
```python
HUGGINGFACE_API_KEY = "your_key_here"
DEEPINFRA_API_KEY = "your_key_here"
# etc.
```

## 🚀 Usage

The chatbot will automatically:
1. Try Cursor API first (if available)
2. Try DeepInfra (most reliable free option)
3. Try Hugging Face
4. Try Together AI
5. Fall back to intelligent keyword matching

## 🧪 Testing

Test the LLM integration:
```python
from llm_handler import get_simple_llm_response

# Test responses
print(get_simple_llm_response("Hello!"))
print(get_simple_llm_response("What's the weather like?"))
print(get_simple_llm_response("Can you analyze https://google.com?"))
```

## 🔧 Troubleshooting

### No API Keys Set
- The chatbot will use intelligent fallback responses
- Still works perfectly for security analysis
- Just less conversational for general questions

### API Rate Limits
- Free tiers have rate limits
- The system automatically falls back to other providers
- No interruption to security analysis functionality

### Cursor API Issues
- Check if you have API access in your Cursor account
- Verify the API endpoint in the code
- Contact Cursor support for API documentation

## 🎯 Features

With LLM integration, your chatbot can now:
- ✅ Answer general questions intelligently
- ✅ Provide time, date, and basic info
- ✅ Engage in casual conversation
- ✅ Maintain security focus
- ✅ Fall back gracefully if APIs fail
- ✅ Still perform all security analysis functions

## 🔒 Security Note

- Never commit API keys to version control
- Use environment variables or .env files
- Add `.env` to your `.gitignore`
- Rotate keys regularly 