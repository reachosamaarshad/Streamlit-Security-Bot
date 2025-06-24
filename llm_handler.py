import requests
import json
import re
from typing import Dict, List, Optional
import time
from config import Config

class LLMHandler:
    def __init__(self):
        self.context = """
        You are SecureLink, a friendly and knowledgeable website security assistant. 
        Your primary role is to help users analyze website security, but you can also 
        engage in casual conversation and answer general questions.
        
        Key capabilities:
        - Website security analysis (HTTPS, SSL, domain age, headers, etc.)
        - General conversation and greetings
        - Basic information about time, weather, etc.
        - Security education and tips
        
        Always be helpful, friendly, and security-focused. If someone asks about 
        website security or provides a URL, offer to analyze it. For other questions, 
        be conversational but remind them of your security expertise.
        """
        
        # Free LLM API endpoints
        self.free_apis = {
            "huggingface": "https://api-inference.huggingface.co/models/",
            "deepinfra": "https://api.deepinfra.com/v1/openai/chat/completions",
            "together": "https://api.together.xyz/v1/chat/completions"
        }
        
        # Simple local keyword-based fallback
        self.security_keywords = [
            'analyze', 'analysis', 'check', 'scan', 'security', 'secure', 'safe',
            'test', 'examine', 'inspect', 'review', 'audit', 'verify', 'validate',
            'assess', 'evaluate', 'investigate', 'look into', 'check out',
            'website', 'url', 'domain', 'ssl', 'https', 'certificate'
        ]
        
        self.greeting_keywords = [
            'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
            'how are you', 'what\'s up', 'sup', 'greetings'
        ]
        
        self.info_keywords = [
            'time', 'weather', 'date', 'temperature', 'location', 'where', 'when'
        ]

    def detect_intent(self, user_input: str) -> Dict:
        """Detect user intent using keyword matching and simple NLP"""
        user_input_lower = user_input.lower()
        
        # Check for URLs
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        urls = url_pattern.findall(user_input)
        
        # Check for security analysis intent
        has_security_keywords = any(keyword in user_input_lower for keyword in self.security_keywords)
        has_url = len(urls) > 0
        
        # Check for greetings
        is_greeting = any(greeting in user_input_lower for greeting in self.greeting_keywords)
        
        # Check for info requests
        is_info_request = any(keyword in user_input_lower for keyword in self.info_keywords)
        
        return {
            'intent': 'security_analysis' if (has_security_keywords or has_url) else 
                     'greeting' if is_greeting else 
                     'info_request' if is_info_request else 'general',
            'urls': urls,
            'confidence': 0.8 if (has_security_keywords or has_url) else 0.6
        }

    def get_response_from_free_api(self, user_input: str, api_type: str = "fallback") -> str:
        """Get response from free LLM APIs"""
        try:
            if api_type == "cursor" and Config.is_llm_available("cursor"):
                return self._call_cursor(user_input)
            elif api_type == "huggingface" and Config.is_llm_available("huggingface"):
                return self._call_huggingface(user_input)
            elif api_type == "deepinfra" and Config.is_llm_available("deepinfra"):
                return self._call_deepinfra(user_input)
            elif api_type == "together" and Config.is_llm_available("together"):
                return self._call_together(user_input)
            else:
                return self._fallback_response(user_input)
        except Exception as e:
            print(f"API call failed: {e}")
            return self._fallback_response(user_input)

    def _call_huggingface(self, user_input: str) -> str:
        """Call Hugging Face Inference API (free tier)"""
        try:
            api_key = Config.get_api_key("huggingface")
            if not api_key:
                return self._fallback_response(user_input)
            
            # Using a simpler, more accessible model
            model = "gpt2"  # This model should work with basic tokens
            url = f"{self.free_apis['huggingface']}{model}"
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Simple input format for GPT-2
            prompt = f"User: {user_input}\nAssistant: I'm SecureLink, your website security assistant. "
            
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_length": 100,
                    "temperature": 0.7,
                    "do_sample": True,
                    "return_full_text": False
                }
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    generated_text = result[0].get('generated_text', '')
                    # Extract just the new generated part
                    if generated_text.startswith(prompt):
                        new_text = generated_text[len(prompt):].strip()
                        if new_text:
                            return new_text
                    
                    # If we can't extract properly, use fallback
                    return self._fallback_response(user_input)
                else:
                    return self._fallback_response(user_input)
            else:
                print(f"Hugging Face API error: {response.status_code} - {response.text}")
                # Try a different approach - use the token for basic inference
                return self._try_simple_huggingface(user_input, api_key)
        except Exception as e:
            print(f"Hugging Face API exception: {e}")
            return self._fallback_response(user_input)

    def _try_simple_huggingface(self, user_input: str, api_key: str) -> str:
        """Try a simpler Hugging Face approach"""
        try:
            # Try with a very basic model
            model = "distilgpt2"
            url = f"{self.free_apis['huggingface']}{model}"
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "inputs": f"User: {user_input}",
                "parameters": {
                    "max_length": 50,
                    "temperature": 0.8
                }
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    generated_text = result[0].get('generated_text', '')
                    if generated_text and len(generated_text) > 10:
                        return f"I understand you said: '{user_input}'. As your security assistant, I'm here to help with website analysis! 🔒"
            
            return self._fallback_response(user_input)
        except:
            return self._fallback_response(user_input)

    def _call_deepinfra(self, user_input: str) -> str:
        """Call DeepInfra API (free tier)"""
        try:
            api_key = Config.get_api_key("deepinfra")
            if not api_key:
                return self._fallback_response(user_input)
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            
            payload = {
                "model": "microsoft/DialoGPT-medium",
                "messages": [
                    {"role": "system", "content": self.context},
                    {"role": "user", "content": user_input}
                ],
                "max_tokens": 200,
                "temperature": 0.7
            }
            
            response = requests.post(self.free_apis["deepinfra"], headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                print(f"DeepInfra API error: {response.status_code} - {response.text}")
                return self._fallback_response(user_input)
        except Exception as e:
            print(f"DeepInfra API exception: {e}")
            return self._fallback_response(user_input)

    def _call_together(self, user_input: str) -> str:
        """Call Together AI API (free credits available)"""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer free"  # You'll need to get free credits
            }
            
            payload = {
                "model": "togethercomputer/llama-2-7b-chat",
                "messages": [
                    {"role": "system", "content": self.context},
                    {"role": "user", "content": user_input}
                ],
                "max_tokens": 200,
                "temperature": 0.7
            }
            
            response = requests.post(self.free_apis["together"], headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return self._fallback_response(user_input)
        except:
            return self._fallback_response(user_input)

    def _call_cursor(self, user_input: str) -> str:
        """Call Cursor API (if you have a paid account)"""
        try:
            api_key = Config.get_api_key("cursor")
            if not api_key:
                return self._fallback_response(user_input)
            
            # Cursor API endpoint (you'll need to check their documentation)
            url = "https://api.cursor.sh/v1/chat/completions"  # Example endpoint
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            
            payload = {
                "model": "gpt-3.5-turbo",  # or whatever model Cursor provides
                "messages": [
                    {"role": "system", "content": self.context},
                    {"role": "user", "content": user_input}
                ],
                "max_tokens": 200,
                "temperature": 0.7
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return self._fallback_response(user_input)
        except:
            return self._fallback_response(user_input)

    def _fallback_response(self, user_input: str) -> str:
        """Fallback response using keyword matching"""
        intent = self.detect_intent(user_input)
        
        if intent['intent'] == 'security_analysis':
            if intent['urls']:
                return f"I'd be happy to analyze the security of {intent['urls'][0]} for you! 🔍 Just let me know if you want me to proceed with a detailed security assessment."
            else:
                return "I'd be happy to analyze a website for you! 🔍 Please provide the URL you'd like me to check for security issues."
        
        elif intent['intent'] == 'greeting':
            greetings = [
                "Hello! 👋 I'm SecureLink, your website security assistant. How can I help you today?",
                "Hi there! 😊 I'm here to help you analyze website security. What would you like to check?",
                "Hey! 👋 Ready to analyze some websites for security? Just let me know what you'd like to check!",
                "Greetings! 🔒 I'm your security assistant. How can I help you with website analysis today?"
            ]
            import random
            return random.choice(greetings)
        
        elif intent['intent'] == 'info_request':
            if 'time' in user_input.lower():
                import datetime
                current_time = datetime.datetime.now().strftime("%H:%M")
                return f"The current time is {current_time}. ⏰ But remember, I'm primarily here to help with website security analysis! 🔒"
            elif 'weather' in user_input.lower():
                return "I can't check the weather, but I can definitely help you analyze website security! 🌤️ Just provide me with a URL to check."
            else:
                return "I'm primarily a website security assistant, but I can help with basic info. What would you like to know? 🔒"
        
        else:
            responses = [
                "I'm SecureLink, your website security assistant! 🔒 I can help you analyze websites for security issues. Just provide me with a URL!",
                "That's interesting! I'm specifically designed to help with website security analysis. Try asking me to check a website URL! 🔍",
                "I'm here to help with website security! 🔒 You can ask me to analyze any website by providing its URL.",
                "I'm your security assistant! I can check websites for security vulnerabilities, SSL certificates, and more. Just give me a URL to analyze! 🔍"
            ]
            import random
            return random.choice(responses)

    def get_response(self, user_input: str) -> str:
        """Main method to get LLM response"""
        if not Config.USE_LLM:
            return self._fallback_response(user_input)
        
        # Try Hugging Face first (primary provider)
        if Config.is_llm_available("huggingface"):
            try:
                response = self.get_response_from_free_api(user_input, "huggingface")
                if response and len(response) > 10:  # Basic validation
                    return response
            except Exception as e:
                print(f"Hugging Face failed: {e}")
        
        # Try other providers as fallback
        providers = ["cursor", "deepinfra", "together", "fallback"]
        
        for provider in providers:
            try:
                if provider == "fallback":
                    return self._fallback_response(user_input)
                
                if Config.is_llm_available(provider):
                    response = self.get_response_from_free_api(user_input, provider)
                    if response and len(response) > 10:  # Basic validation
                        return response
            except Exception as e:
                print(f"Provider {provider} failed: {e}")
                continue
        
        # Final fallback
        return self._fallback_response(user_input)

# For testing without API keys
def get_simple_llm_response(user_input: str) -> str:
    """Simple LLM-like response using pattern matching and templates"""
    handler = LLMHandler()
    return handler.get_response(user_input) 