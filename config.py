# Configuration file for API keys and settings
import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Free LLM API Keys (get these from respective platforms)
    HUGGINGFACE_API_KEY: Optional[str] = os.getenv("HUGGINGFACE_API_KEY", "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")
    DEEPINFRA_API_KEY: Optional[str] = os.getenv("DEEPINFRA_API_KEY", None)
    TOGETHER_API_KEY: Optional[str] = os.getenv("TOGETHER_API_KEY", None)
    
    # Cursor API (if you have a paid account)
    CURSOR_API_KEY: Optional[str] = os.getenv("CURSOR_API_KEY", None)
    
    # App Settings
    USE_LLM: bool = True  # Set to False to use only rule-based responses
    LLM_PROVIDER: str = "huggingface"  # Set Hugging Face as primary provider
    
    # Security Analysis Settings
    MAX_ANALYSIS_TIME: int = 30  # seconds
    ENABLE_WHOIS: bool = True
    ENABLE_DNS: bool = True
    
    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for specified provider"""
        key_map = {
            "huggingface": cls.HUGGINGFACE_API_KEY,
            "deepinfra": cls.DEEPINFRA_API_KEY,
            "together": cls.TOGETHER_API_KEY,
            "cursor": cls.CURSOR_API_KEY
        }
        return key_map.get(provider)
    
    @classmethod
    def is_llm_available(cls, provider: str) -> bool:
        """Check if LLM provider is available"""
        if not cls.USE_LLM:
            return False
        
        if provider == "fallback":
            return True
        
        return cls.get_api_key(provider) is not None 