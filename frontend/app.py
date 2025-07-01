import os
import re
import socket
import json
import traceback
import math
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import Counter
import requests
import numpy as np
import tensorflow as tf
import pickle
import h5py  
from flask import Flask, jsonify, request, render_template, session, flash, redirect, url_for, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
import ssl
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional, Union, Any
from difflib import SequenceMatcher
import sys
import flask
from dotenv import load_dotenv

load_dotenv()
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Attempt to import Firebase 
try:
    import firebase_admin
    from firebase_admin import credentials, auth
    firebase_available = True
    logger.info("Firebase authentication is available")
except ImportError:
    firebase_available = False
    logger.warning("Firebase authentication is not available - continuing without authentication")
    # Create empty placeholder classes to avoid errors
    class credentials:
        @staticmethod
        def Certificate(path):
            return None
    
    class auth:
        pass
    
    class firebase_admin:
        @staticmethod
        def initialize_app(cred=None):
            return None
        
        @staticmethod
        def get_app():
            raise ValueError("Firebase app not available")

# Try to import whois for domain registration data
try:
    import whois
    whois_available = True
    logger.info("python-whois is available for domain registration checks")
except ImportError:
    whois_available = False
    logger.warning("python-whois not available, domain age features will be limited")

# Import model service - using direct path instead of package import
import os.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model_service import get_model, get_scaler, get_status, predict

# Add Beautiful Soup import
try:
    from bs4 import BeautifulSoup
    BeautifulSoup_available = True
    logger.info("BeautifulSoup is available for HTML analysis")
except ImportError:
    BeautifulSoup_available = False
    logger.warning("BeautifulSoup not available, HTML security checks will be limited")
    BeautifulSoup = None

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-secret-key')

# Initialize Firebase only if it's available
if firebase_available:
    try:
        # Debug: Print the credential path and check if it exists
        cred_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
        logger.info(f"FIREBASE_CREDENTIALS_PATH: {cred_path}")
        if cred_path:
            logger.info(f"Credential file exists: {os.path.exists(cred_path)}")
        # Check if Firebase app is already initialized
        default_app = firebase_admin.get_app()
        logger.info("Using existing Firebase app")
    except ValueError:
        # Initialize with default configuration when running locally
        try:
            # Try to use certificate if path is provided
            cred_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
            if cred_path and os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
                logger.info(f"Initialized Firebase with credentials from {cred_path}")
            else:
                # Initialize with default configuration
                firebase_admin.initialize_app()
                logger.info("Initialized Firebase with default configuration")
        except Exception as e:
            logger.warning(f"Failed to initialize Firebase: {e}")
            logger.warning("Continuing without Firebase authentication")
else:
    logger.warning("Firebase not available, authentication features will be limited")

# Global variables for model and scaler access
def get_model_instance():
    return get_model()

def get_scaler_instance():
    return get_scaler()

def is_ip(domain):
    """
    Check if the domain is an IP address
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if the domain is an IP address, False otherwise
    """
    # IPv4 pattern
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    
    match = re.match(pattern, domain)
    if not match:
        return False
    
    # Check that each octet is valid (0-255)
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False
    
    return True

def calculate_entropy(string):
    """
    Calculate the Shannon entropy of a string to measure randomness
    
    Args:
        string (str): Input string
        
    Returns:
        float: Shannon entropy value
    """
    if not string:
        return 0
    
    # Count character occurrences
    counts = Counter(string)
    # Calculate frequencies
    frequencies = [count/len(string) for count in counts.values()]
    # Calculate entropy
    entropy = -sum(f * math.log2(f) for f in frequencies)
    
    return entropy

def check_suspicious_patterns(url):
    """Check for suspicious patterns in a URL that may indicate phishing"""
    suspicious_patterns = []
    
    try:
        # Parse URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Check for HTTP instead of HTTPS
        if parsed_url.scheme == 'http':
            suspicious_patterns.append({
                "pattern": "Insecure HTTP protocol",
                "severity": "high",
                "explanation": "The site uses HTTP instead of HTTPS, which means the connection is not encrypted.",
                "risk_score": 15
            })
        
        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'online', 'site', 'club', 'icu', 'pw', 'rest', 'zip']
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in suspicious_tlds:
            suspicious_patterns.append({
                "pattern": f"Suspicious TLD: '{tld}'",
                "severity": "medium",
                "explanation": f"The domain uses a TLD ('{tld}') that is commonly associated with free domains and frequently used in phishing attacks.",
                "risk_score": 10
            })
        
        # Check for numeric subdomain or long subdomain
        subdomain_parts = domain.split('.')
        if len(subdomain_parts) > 2:
            subdomain = '.'.join(subdomain_parts[:-2])
            if subdomain.isdigit() or re.match(r'^\d+-\d+-\d+', subdomain):
                suspicious_patterns.append({
                    "pattern": "Numeric subdomain pattern",
                    "severity": "medium",
                    "explanation": "The URL uses a numeric pattern in the subdomain, which is often seen in automatically generated phishing domains.",
                    "risk_score": 10
                })
            elif len(subdomain) > 20:
                suspicious_patterns.append({
                    "pattern": "Unusually long subdomain",
                    "severity": "medium",
                    "explanation": "The subdomain is unusually long, which is often a characteristic of phishing URLs trying to obscure their true nature.",
                    "risk_score": 5
                })
        
        # Check for URL shortening services
        shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 
                              'buff.ly', 'ow.ly', 'rebrand.ly', 'tr.im']
        # Modified check to prevent false positives
        is_shortener = False
        domain_parts = domain.split('.')
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain
        
        # First check exact domain match
        if any(base_domain == service for service in shortening_services):
            is_shortener = True
        # Then check subdomain match (e.g., sub.bit.ly)
        elif any(domain.endswith('.' + service) for service in shortening_services):
            is_shortener = True
            
        if is_shortener:
            suspicious_patterns.append({
                "pattern": "URL shortening service",
                "severity": "medium",
                "explanation": "The URL uses a shortening service, which can hide the actual destination.",
                "risk_score": 8
            })
        
        # Check for suspicious words in URL
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
                            'password', 'credential', 'wallet', 'authenticate', 'verification',
                            'banking', 'security', 'alert', 'suspended', 'unusual']
        found_words = [word for word in suspicious_words if word in url.lower()]
        if found_words:
            words_str = ', '.join(found_words)
            suspicious_patterns.append({
                "pattern": f"Suspicious keywords: {words_str}",
                "severity": "medium",
                "explanation": f"The URL contains words often associated with phishing attempts that try to create urgency or request credentials.",
                "risk_score": 12
            })
            
        # Check for IP address as domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            suspicious_patterns.append({
                "pattern": "IP address used as domain",
                "severity": "high",
                "explanation": "The URL uses an IP address instead of a domain name, which is rarely done for legitimate websites and often indicates phishing.",
                "risk_score": 25
            })
            
        # Check for excessive number of dots in domain
        if domain.count('.') > 3:
            suspicious_patterns.append({
                "pattern": "Excessive subdomains",
                "severity": "medium",
                "explanation": "The URL contains an unusually high number of subdomains, which can be an attempt to confuse users.",
                "risk_score": 8
            })
            
        # Check for excessive URL length
        if len(url) > 100:
            suspicious_patterns.append({
                "pattern": "Excessively long URL",
                "severity": "medium",
                "explanation": "The URL is unusually long, which can be an attempt to hide suspicious elements.",
                "risk_score": 5
            })
            
        # Check for presence of @ symbol in URL
        if '@' in url:
            suspicious_patterns.append({
                "pattern": "@ symbol in URL",
                "severity": "high",
                "explanation": "The URL contains an @ symbol, which can be used to trick users by hiding the actual destination.",
                "risk_score": 20
            })
            
        # Check for excessive number of special characters
        special_char_count = sum(c in '!@#$%^&*()_+-={}[]|\\:;"\'<>,.?/' for c in url)
        if special_char_count > 15:
            suspicious_patterns.append({
                "pattern": "Excessive special characters",
                "severity": "medium",
                "explanation": "The URL contains an unusually high number of special characters, which can be an attempt to obfuscate malicious content.",
                "risk_score": 10
            })
            
        # If no patterns were found but domain can't be resolved
        if not suspicious_patterns:
            try:
                socket.gethostbyname(domain)
            except:
                suspicious_patterns.append({
                    "pattern": "Domain does not resolve",
                    "severity": "high",
                    "explanation": "The domain cannot be resolved to an IP address, which means it may not exist or may be newly registered for phishing.",
                    "risk_score": 20
                })
        
        logger.info(f"Suspicious patterns found for {url}: {len(suspicious_patterns)}")
        return suspicious_patterns
    except Exception as e:
        logger.error(f"Error checking suspicious patterns: {e}")
        return []

def rule_based_prediction(url, scaled_features=None):
    """
    Rule-based prediction when model is unavailable
    
    Args:
        url: URL to analyze
        scaled_features: Optional feature array
        
    Returns:
        float: Risk score (0-100)
    """
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # Initialize risk score
        risk_score = 0
        risk_factors = {}
        
        # 1. Basic protocol check (part of URL features - 40%)
        if parsed_url.scheme != 'https':
            risk_score += 20
            risk_factors["insecure_protocol"] = {
                "description": "The site uses HTTP instead of HTTPS",
                "impact": "high",
                "contribution": 20
            }
        
        # 2. Domain-based checks (part of URL features - 40%)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            # IP address as domain
            risk_score += 25
            risk_factors["ip_as_domain"] = {
                "description": "IP address used as domain instead of a domain name",
                "impact": "high",
                "contribution": 25
            }
        
        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'online', 'site']
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in suspicious_tlds:
            risk_score += 15
            risk_factors["suspicious_tld"] = {
                "description": f"Domain uses suspicious TLD (.{tld})",
                "impact": "medium",
                "contribution": 15
            }
        
        # Check domain length
        if len(domain) > 30:
            risk_score += 10
            risk_factors["long_domain"] = {
                "description": "Unusually long domain name",
                "impact": "medium",
                "contribution": 10
            }
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            risk_score += 15
            risk_factors["excessive_subdomains"] = {
                "description": f"Domain has {domain.count('.')} subdomains",
                "impact": "medium",
                "contribution": 15
            }
        
        # 3. URL structure checks (part of URL features - 40%)
        if len(url) > 100:
            risk_score += 10
            risk_factors["long_url"] = {
                "description": "Excessively long URL",
                "impact": "medium",
                "contribution": 10
            }
        
        # Check for suspicious keywords
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
                            'password', 'credential', 'wallet', 'authenticate', 'verification']
        keyword_count = 0
        for word in suspicious_words:
            if word in url.lower():
                keyword_count += 1
                risk_score += 5
                # Cap keyword penalty at 30
                if risk_score > 30:
                    break
                    
        if keyword_count > 0:
            risk_factors["suspicious_keywords"] = {
                "description": f"URL contains {keyword_count} suspicious keywords",
                "impact": "medium",
                "contribution": min(keyword_count * 5, 30)
            }
        
        # Check special characters
        special_char_count = sum(c in '!@#$%^&*()_+-={}[]|\\:;"\'<>,.?/' for c in url)
        risk_score += min(special_char_count, 15)
        
        if special_char_count > 5:
            risk_factors["special_chars"] = {
                "description": f"URL contains {special_char_count} special characters",
                "impact": "low" if special_char_count < 10 else "medium",
                "contribution": min(special_char_count, 15)
            }
        
        # Check for URL shortening services
        shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd']
        if any(service in domain for service in shortening_services):
            risk_score += 15
            risk_factors["url_shortener"] = {
                "description": "Uses URL shortening service",
                "impact": "medium",
                "contribution": 15
            }
        
        # 4. Check if trusted domain
        if is_trusted_domain(url):
            risk_score = max(0, risk_score - 40)  # Significant reduction for trusted domains
            risk_factors["trusted_domain"] = {
                "description": "Domain is in trusted list",
                "impact": "positive",
                "contribution": -40
            }
        
        # 5. Add results from suspicious patterns check (30%)
        suspicious_patterns = check_suspicious_patterns(url)
        pattern_risk = sum(p.get("risk_score", 0) for p in suspicious_patterns)
        risk_score += pattern_risk
        
        if pattern_risk > 0:
            risk_factors["suspicious_patterns"] = {
                "description": f"Found {len(suspicious_patterns)} suspicious patterns",
                "impact": "high" if pattern_risk > 20 else "medium",
                "contribution": pattern_risk
            }
        
        # 6. Try to resolve domain (part of domain information - 10%)
        domain_info = get_domain_info(url)
        domain_penalty = 0
        
        if domain_info.get("ip_address") == "Could not resolve":
            # Domain cannot be resolved, apply significant penalty
            domain_penalty = 10  # 10% of total score as penalty
            risk_score += domain_penalty
            risk_factors["unresolvable_domain"] = {
                "description": "Domain could not be resolved to an IP address",
                "impact": "high",
                "contribution": domain_penalty
            }
        else:
            # Check country risk if domain could be resolved
            high_risk_countries = ["RU", "CN", "IR", "KP", "NG"]
            country = domain_info.get("country", "Unknown")
            
            if country in high_risk_countries:
                country_penalty = 5
                risk_score += country_penalty
                risk_factors["high_risk_country"] = {
                    "description": f"Domain hosted in high-risk country ({country})",
                    "impact": "medium",
                    "contribution": country_penalty
                }
        
        # 7. Consider HTML content risk if available (20%)
        try:
            html_security = check_html_security(url)
            html_risk = html_security.get("content_score", 0) / 5  # Scale down from 0-100 to 0-20
            risk_score += html_risk
            
            if html_risk > 0:
                risk_factors["html_content"] = {
                    "description": f"HTML content has suspicious elements",
                    "impact": "high" if html_risk > 10 else "medium",
                    "contribution": html_risk
                }
        except Exception as e:
            logger.error(f"Error checking HTML security: {e}")
        
        # Ensure final score is within 0-100 range
        final_score = max(0, min(100, risk_score))
        
        # Create the result dictionary
        result = {
            "status": "success",
            "url": url,
            "score": final_score,
            "risk_level": get_risk_level(final_score),
            "risk_factors": risk_factors,
            "using_fallback": True,
            "domain_info": domain_info,
            "suspicious_patterns": suspicious_patterns
        }
        
        return result
    except Exception as e:
        logger.error(f"Error in rule_based_prediction: {e}")
        # Default moderate risk on error
        return {
            "status": "error",
            "url": url,
            "score": 50,  # Default moderate risk
            "risk_level": get_risk_level(50),
            "using_fallback": True,
            "error": str(e)
        }

def is_trusted_domain(url):
    """
    Check if a URL belongs to a trusted domain
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if the domain is trusted, False otherwise
    """
    try:
        # Parse the URL to extract the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # List of trusted domains
        trusted_domains = [
            'google.com', 'gmail.com', 'youtube.com',
            'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'microsoft.com', 'office.com', 'outlook.com', 'linkedin.com',
            'apple.com', 'icloud.com', 'amazon.com', 'paypal.com',
            'github.com', 'dropbox.com', 'netflix.com', 'spotify.com',
            'wikipedia.org', 'adobe.com', 'cloudflare.com',
            'wordpress.com', 'yahoo.com', 'twitch.tv',
            'reddit.com', 'pinterest.com', 'ebay.com',
            'zoom.us', 'slack.com', 'shopify.com'
        ]
        
        # Check if domain ends with any trusted domain
        return any(domain == td or domain.endswith('.' + td) for td in trusted_domains)
    except Exception as e:
        logger.error(f"Error in is_trusted_domain: {e}")
        return False

# Create a custom InputLayer that can handle batch_shape
class CompatibleInputLayer(tf.keras.layers.InputLayer):
    def __init__(self, **kwargs):
        # Handle the batch_shape case
        if 'batch_shape' in kwargs:
            input_shape = kwargs.pop('batch_shape')
            if input_shape is not None and len(input_shape) > 1:
                kwargs['input_shape'] = input_shape[1:]
        super().__init__(**kwargs)

def tld_risk_score(tld: str) -> float:
    """
    Calculate risk score for top-level domains.
    Some TLDs are more associated with fraudulent activity than others.
    
    Args:
        tld: Top-level domain (e.g., 'com', 'org')
        
    Returns:
        float: Risk score between 0 and 1
    """
    risky_tlds = {
        'xyz': 0.7, 'top': 0.65, 'loan': 0.85, 'bid': 0.8, 
        'online': 0.75, 'site': 0.7, 'club': 0.65, 'stream': 0.8,
        'icu': 0.75, 'live': 0.6, 'vip': 0.7, 'fit': 0.6,
        'tk': 0.8, 'ml': 0.75, 'ga': 0.75, 'cf': 0.7
    }
    return risky_tlds.get(tld.lower(), 0.2)

def extract_features(url: str):
    """
    Extract features from a URL for machine learning prediction
    
    Args:
        url: URL to analyze
        
    Returns:
        tuple: (feature_dict, feature_array)
    """
    logger.info(f"Extracting features for URL: {url}")
    
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Basic URL components
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        fragment = parsed_url.fragment.lower()
        
        # Basic Feature extraction (original features)
        # Length-based features
        url_length = len(url)
        domain_length = len(domain)
        path_length = len(path)
        query_length = len(query)
        fragment_length = len(fragment)
        
        # Domain-based features
        subdomain_count = domain.count('.') - 1 if '.' in domain else 0
        subdomain_count = max(0, subdomain_count)  # Ensure non-negative
        
        # Path-based features
        path_depth = path.count('/') if path else 0
        
        # Get TLD risk score
        tld = domain.split('.')[-1] if '.' in domain else ''
        tld_score = tld_risk_score(tld)
        
        # Calculate entropy as a measure of randomness
        domain_entropy = calculate_entropy(domain)
        
        # Security features
        https_present = 1 if parsed_url.scheme == 'https' else 0
        
        # Character-based features
        special_char_count = sum(c in '!@#$%^&*()_+-={}[]|\\:;"\'<>,.?/' for c in url)
        digit_count = sum(c.isdigit() for c in url)
        letter_count = sum(c.isalpha() for c in url)
        
        digit_percentage = (digit_count / len(url)) * 100 if len(url) > 0 else 0
        letter_percentage = (letter_count / len(url)) * 100 if len(url) > 0 else 0
        
        # Check if path is all numeric
        numeric_path = 1 if path and all(c.isdigit() or c == '/' for c in path) else 0
        
        # Suspicious patterns
        ip_url = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        
        # Looking for suspicious keywords
        suspicious_keywords = ['login', 'signin', 'account', 'secure', 'update', 'verify', 
                              'confirm', 'banking', 'payment', 'wallet', 'ebay', 'paypal']
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        # Create a dictionary of basic feature names and values
        basic_features = {
            "url_length": url_length,
            "domain_length": domain_length,
            "path_length": path_length,
            "query_length": query_length,
            "fragment_length": fragment_length,
            "subdomain_count": subdomain_count,
            "path_depth": path_depth,
            "tld_score": tld_score,
            "domain_entropy": domain_entropy,
            "https_present": https_present,
            "special_char_count": special_char_count,
            "digit_percentage": digit_percentage,
            "letter_percentage": letter_percentage,
            "numeric_path": numeric_path,
            "ip_url": ip_url,
            "keyword_count": keyword_count
        }
        
        # Get domain information for additional features
        domain_info = get_domain_info(url)
        ip_address = domain_info.get("ip_address", "Unknown")
        
        # NEW: Extract enhanced features
        whois_features = extract_whois_features(domain)
        nlp_features = extract_nlp_features(domain)
        reputation_features = extract_reputation_features(domain, ip_address)
        
        # Try to get content features - might fail if site is down
        content_features = {}
        html_security = {}
        try:
            # Reuse HTML content if we can get it once
            response = requests.get(url, timeout=10, 
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            html_content = response.text
            
            # Extract content features from the HTML
            content_features = extract_content_features(url, html_content)
            
            # Get HTML security data
            if BeautifulSoup_available:
                html_security_data = check_html_security(url, html_content)
                html_security = {
                    "security_score": html_security_data.get("content_score", 0),
                    "risk_factor_count": len(html_security_data.get("risk_factors", [])),
                    "has_password_field": 1 if any("password" in rf.lower() for rf in html_security_data.get("risk_factors", [])) else 0,
                    "has_obfuscated_js": 1 if any("obfuscated" in rf.lower() for rf in html_security_data.get("risk_factors", [])) else 0
                }
        except Exception as content_error:
            logger.warning(f"Could not extract content features: {content_error}")
            content_features = extract_content_features(url)  # Empty defaults
            html_security = {"security_score": 0, "risk_factor_count": 0, "has_password_field": 0, "has_obfuscated_js": 0}
            
        # Try to get certificate transparency log features
        ct_features = extract_ct_log_features(domain)
        
        # Combine all features into a single dictionary
        all_features = {**basic_features}
        
        # Add new feature groups with prefixes to avoid name collisions
        for key, value in whois_features.items():
            all_features[f"whois_{key}"] = value
            
        for key, value in nlp_features.items():
            all_features[f"nlp_{key}"] = value
            
        for key, value in reputation_features.items():
            all_features[f"rep_{key}"] = value
            
        for key, value in content_features.items():
            all_features[f"content_{key}"] = value
            
        for key, value in html_security.items():
            all_features[f"html_{key}"] = value
            
        for key, value in ct_features.items():
            all_features[f"ct_{key}"] = value
            
        # Add additional domain info features
        all_features["geo_suspicious_country"] = 1 if domain_info.get("country") in ["RU", "CN", "IR", "KP"] else 0
            
        # Convert feature dictionary to array for the model
        # Extract values in a stable order for the model
        basic_feature_values = list(basic_features.values())
        
        # Create a list of values for the additional features
        additional_values = []
        for key in sorted(all_features.keys()):
            if key not in basic_features:
                additional_values.append(all_features[key])
        
        # Full feature array - basic features plus new features
        full_features = basic_feature_values + additional_values
        
        # Convert to numpy array
        base_features = np.array(full_features, dtype=np.float32)
        
        # Pad to expected size for model compatibility (should be 96 for your model)
        # Adjust padding as needed based on your model's expectations
        padding_size = max(0, 96 - len(full_features))
        if padding_size > 0:
            padding = np.zeros(padding_size, dtype=np.float32)
            feature_array = np.concatenate([base_features, padding])
        else:
            # If we have more features than expected, truncate to 96
            feature_array = base_features[:96]
        
        # Log feature count
        logger.info(f"Extracted {len(full_features)} features, adjusted to {len(feature_array)} for model compatibility")
        
        return all_features, feature_array
        
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        logger.error(traceback.format_exc())
        # Return default values in case of error
        feature_dict = {"error": str(e)}
        feature_array = np.zeros(96, dtype=np.float32)
        return feature_dict, feature_array

def check_html_security(url, html_content=None):
    """
    Check HTML content for suspicious or malicious patterns
    
    Args:
        url: URL to analyze
        html_content: Optional pre-fetched HTML content
        
    Returns:
        dict: Dictionary with security information
    """
    if not BeautifulSoup_available:
        return {
            "error": "BeautifulSoup not available",
            "content_score": 0,
            "risk_factors": ["Unable to analyze HTML content - BeautifulSoup not installed"]
        }
    
    try:
        # Get the HTML content if not provided) 
        if html_content is None:
            response = requests.get(url, timeout=10, 
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            html_content = response.text
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Initialize security data
        security_data = {
            "content_score": 0,  # 0-100 scale, higher means more risky
            "risk_factors": [],  # List of risk factors found
            "security_checks": []  # List of security checks passed
        }
        
        # Check 1: Forms without HTTPS action
        forms = soup.find_all("form")
        insecure_forms = [f for f in forms if f.get('action') and f.get('action').startswith('http://')]
        
        if insecure_forms:
            security_data["content_score"] += 30
            security_data["risk_factors"].append(f"Found {len(insecure_forms)} form(s) submitting to insecure HTTP")
        
        # Check 2: Password inputs
        password_inputs = soup.find_all("input", {"type": "password"})
        if password_inputs:
            security_data["content_score"] += 15
            security_data["risk_factors"].append(f"Found {len(password_inputs)} password input(s)")
            
            # Check if password input is in an insecure form
            for p_input in password_inputs:
                parent_form = p_input.find_parent("form")
                if parent_form and parent_form.get('action') and parent_form.get('action').startswith('http://'):
                    security_data["content_score"] += 25
                    security_data["risk_factors"].append("Password being submitted over insecure HTTP")
                    break
        
        # Check 3: Hidden inputs with suspicious names
        suspicious_hidden = soup.find_all("input", {"type": "hidden", "name": re.compile(r'user|email|account|pass|auth|token|id|login', re.I)})
        if suspicious_hidden:
            security_data["content_score"] += 10
            security_data["risk_factors"].append(f"Found {len(suspicious_hidden)} hidden fields with suspicious names")
        
        # Check 4: Scripts with suspicious URLs or obfuscated code
        scripts = soup.find_all("script")
        obfuscated_scripts = 0
        suspicious_urls = 0
        
        for script in scripts:
            if script.string:
                # Check for obfuscated code patterns
                if re.search(r'eval\(', script.string) or re.search(r'\\x[0-9a-f]{2}', script.string):
                    obfuscated_scripts += 1
                
                # Check for suspicious URLs in scripts
                if re.search(r'(https?://[^\'"]+\.(xyz|tk|ml|ga|cf|gq|top))', script.string):
                    suspicious_urls += 1
        
        if obfuscated_scripts > 0:
            security_data["content_score"] += 20
            security_data["risk_factors"].append(f"Found {obfuscated_scripts} script(s) with potentially obfuscated code")
        
        if suspicious_urls > 0:
            security_data["content_score"] += 15
            security_data["risk_factors"].append(f"Found {suspicious_urls} script(s) with suspicious URLs")
        
        # Check 5: Excessive use of iframes
        iframes = soup.find_all("iframe")
        if len(iframes) > 3:
            security_data["content_score"] += 10
            security_data["risk_factors"].append(f"Excessive use of iframes ({len(iframes)} found)")
        
        # Add passed security checks
        if not insecure_forms:
            security_data["security_checks"].append("No insecure forms found")
        
        if not password_inputs:
            security_data["security_checks"].append("No password inputs found")
        
        if security_data["content_score"] < 20:
            security_data["security_checks"].append("Low-risk HTML content")
        
        # Add HTTPS security check if URL uses HTTPS
        if url.startswith("https://"):
            security_data["security_checks"].append("HTTPS protocol used")
        
        return security_data
    except Exception as e:
        logger.error(f"Error checking HTML security: {e}")
        return {
            "error": str(e),
            "content_score": 0,
            "risk_factors": [f"Error analyzing HTML content: {str(e)}"]
        }

def predict_with_model(url, features=None):
    """
    Make a prediction using the loaded model.
    If model is not available, falls back to rule-based prediction.
    
    Args:
        url: URL to predict
        features: Optional pre-computed features
        
    Returns:
        dict: Prediction result with risk score and details
    """
    try:
        logger.info(f"Making prediction for URL: {url}")
        
        # Extract features if not provided
        if features is None:
            logger.info("No features provided, extracting new features")
            features, feature_vector = extract_features(url)
        else:
            logger.info(f"Features provided, type: {type(features)}")
            # The feature parameter might be just the dictionary without the feature_vector
            # Always re-extract to get the proper numpy array
            _, feature_vector = extract_features(url)
        
        # Initialize response
        result = {
            "status": "success",
            "url": url,
            "score": 0,
            "risk_level": "Unknown",
            "feature_contributions": [],
            "risk_factors": {},
            "domain_info": {},
            "suspicious_patterns": []
        }
        
        # Check if model is available
        if get_model_instance() is not None and get_scaler_instance() is not None:
            try:
                # Ensure feature_vector is a numpy array before reshaping
                if not isinstance(feature_vector, np.ndarray):
                    logger.error(f"feature_vector is not a numpy array: {type(feature_vector)}")
                    # Fall back to rule-based prediction
                    return rule_based_prediction(url, features)
                
                # Prepare feature vector for prediction
                features_reshaped = feature_vector.reshape(1, -1)
                logger.info(f"Feature shape: {features_reshaped.shape}")
                
                # Scale features if scaler is available
                scaled_features = get_scaler_instance().transform(features_reshaped)
                
                # Make prediction
                prediction = get_model_instance().predict(scaled_features)
                raw_score = float(prediction[0][0]) if hasattr(prediction, 'shape') else float(prediction)
                score = raw_score * 100  # Convert to percentage
                
                logger.info(f"Model prediction raw score: {raw_score}, scaled: {score}")
                
                # Set result fields
                result["score"] = score
                result["raw_score"] = raw_score
                result["risk_level"] = get_risk_level(score)
                
                # Handle unresolvable domains - apply domain information penalty (10% of total score)
                domain_info = get_domain_info(url)
                if domain_info.get("ip_address") == "Could not resolve":
                    # Apply domain information penalty (add up to 10 points to the risk score)
                    domain_penalty = 10.0  # Maximum penalty for unresolvable domains (10% of total score)
                    original_score = score
                    score = min(100, score + domain_penalty)  # Cap at 100
                    result["score"] = score
                    logger.info(f"Domain could not be resolved, applying penalty: {original_score} -> {score}")
                    
                    # Add a risk factor for unresolvable domain
                    if "risk_factors" not in result:
                        result["risk_factors"] = {}
                    result["risk_factors"]["unresolvable_domain"] = {
                        "description": "Domain could not be resolved to an IP address",
                        "impact": "high",
                        "contribution": domain_penalty
                    }
                
                # Feature name mapping to user-friendly names
                feature_name_map = {
                    "url_length": "URL Length",
                    "domain_length": "Domain Length",
                    "path_length": "Path Length",
                    "query_length": "Query Parameters Length",
                    "fragment_length": "Fragment Length",
                    "subdomain_count": "Number of Subdomains",
                    "path_depth": "Path Depth",
                    "tld_score": "Risky TLD Score",
                    "domain_entropy": "Domain Entropy",
                    "https_present": "Security Weights",
                    "special_char_count": "Special Characters",
                    "digit_percentage": "Digit Percentage",
                    "letter_percentage": "Letter Percentage",
                    "numeric_path": "Numeric Path Present",
                    "ip_url": "IP as Domain",
                    "keyword_count": "Suspicious Keywords",
                    # Content feature friendly names
                    "content_page_size_bytes": "Page Size",
                    "content_external_resources_count": "External Resource Count",
                    "content_form_count": "Form Count",
                    "content_password_field_count": "Password Fields",
                    "content_js_to_html_ratio": "JavaScript to HTML Ratio",
                    "content_title_brand_mismatch": "Title-Domain Mismatch",
                    "content_favicon_exists": "Favicon Present",
                    "content_similar_domain_redirect": "Similar Domain Redirect",
                    # HTML security feature friendly names
                    "html_security_score": "HTML Security Score",
                    "html_risk_factor_count": "Security Risk Factor Count",
                    "html_has_password_field": "Contains Password Field",
                    "html_has_obfuscated_js": "Contains Obfuscated JavaScript",
                    # SSL certificate feature friendly names
                    "ct_suspicious_cert_pattern": "Suspicious Certificate Pattern",
                    # Geographic feature friendly names
                    "geo_suspicious_country": "Suspicious Country"
                }
                
                # Add feature contributions
                result["feature_contributions"] = []
                if isinstance(features, dict):
                    for name, value in features.items():
                        if name != "error":
                            # Estimate contribution based on feature value and type
                            contribution = 0.0
                            section = "Key Risk Factors"  # Default section
                            
                            # ====== Core URL & Domain Features (High Impact) ======
                            if name == "url_length" and value > 50:
                                contribution = 0.1 * (value / 100)
                                section = "Key Risk Factors"
                            elif name == "domain_length" and value > 15:
                                contribution = 0.15 * (value / 30)
                                section = "Key Risk Factors"
                            elif name == "domain_entropy" and value > 0:
                                contribution = 0.1 * min(value / 3.0, 1.0)
                                section = "Key Risk Factors"
                            elif name == "special_char_count" and value > 3:
                                contribution = 0.1 * (value / 10)
                                section = "Key Risk Factors"
                            elif name == "tld_score" and value > 0:
                                contribution = 0.15 * value / 0.5  # Scale based on value
                                section = "Key Risk Factors"
                            elif name == "https_present" and value < 1:
                                contribution = 24.6  # Fixed percentage for consistency
                                section = "Key Risk Factors"
                            
                            # ====== Domain Reputation & WHOIS Features (Important) ======
                            elif name == "rep_domain_age_category" and value < 2:
                                contribution = 0.15 * (2 - value) / 2  # Newer domains are riskier
                                section = "Domain Information"
                            elif name == "rep_suspicious_tld_category" and value > 0:
                                contribution = 0.15 * value  # TLD category risk
                                section = "Domain Information"
                            elif name == "rep_suspicious_country" and value > 0:
                                contribution = 0.15  # Suspicious country
                                section = "Domain Information"
                            elif name == "whois_recently_registered" and value > 0:
                                contribution = 0.2  # Recently registered domains are highly suspicious
                                section = "Domain Information"
                            
                            # ====== Critical HTML Content Features (Highest Impact) ======
                            elif name == "content_form_count" and value > 0:
                                contribution = 0.15 * min(value / 2, 1.0)  # Forms are key phishing indicators
                                section = "Suspicious Patterns"
                            elif name == "content_password_field_count" and value > 0:
                                contribution = 0.3 * min(value / 2.0, 1.0)  # Password fields are critical for phishing
                                section = "Suspicious Patterns"
                            elif name == "content_external_resources_count" and value > 3:
                                contribution = 0.12 * min(value / 15, 1.0)  # External resources
                                section = "Suspicious Patterns"
                            elif name == "content_js_to_html_ratio" and value > 0.3:
                                contribution = 0.15 * min(value / 0.5, 1.0)  # High JS ratio can indicate obfuscation
                                section = "Suspicious Patterns"
                            elif name == "content_title_brand_mismatch" and value > 0:
                                contribution = 0.2  # Title not matching domain is suspicious
                                section = "Suspicious Patterns"
                            elif name == "content_similar_domain_redirect" and value > 0:
                                contribution = 0.35  # Redirects to similar domains are highly suspicious
                                section = "Suspicious Patterns"
                            elif name == "content_favicon_exists" and value < 1:
                                contribution = 0.08  # Missing favicon often indicates phishing
                                section = "Key Risk Factors"
                            
                            # ====== HTML Security Metrics (High Impact) ======
                            elif name == "html_security_score" and value > 0:
                                contribution = 0.2 * min(value / 50, 1.0)  # Overall security score
                                section = "Suspicious Patterns"
                            elif name == "html_risk_factor_count" and value > 0:
                                contribution = 0.15 * min(value / 3, 1.0)  # Number of risks found
                                section = "Suspicious Patterns"
                            elif name == "html_has_password_field" and value > 0:
                                contribution = 0.25  # Password fields in HTML are suspicious
                                section = "Suspicious Patterns"
                            elif name == "html_has_obfuscated_js" and value > 0:
                                contribution = 0.3  # Obfuscated JavaScript is highly suspicious
                                section = "Suspicious Patterns"
                            
                            # ====== SSL Certificate Features (Medium Impact) ======
                            elif name == "ct_suspicious_cert_pattern" and value > 0:
                                contribution = 0.15  # Suspicious certificate patterns
                                section = "Domain Information"
                            
                            # ====== Geographic Features (Medium Impact) ======
                            elif name == "geo_suspicious_country" and value > 0:
                                contribution = 0.15  # Suspicious country
                                section = "Domain Information"
                            
                            # Use friendly name if available
                            display_name = feature_name_map.get(name, name.replace("_", " ").title())
                            
                            # Determine color based on contribution
                            color_class = "success"  # Default green
                            if contribution > 60:
                                color_class = "danger"  # Red for high risk
                            elif contribution > 20:
                                color_class = "warning"  # Orange for medium risk
                            
                            result["feature_contributions"].append({
                                "name": name,
                                "value": value,
                                "contribution": contribution,
                                "direction": "increases" if contribution > 0 else "decreases",
                                "percentage": contribution,  # No need to convert for HTTPS present
                                "feature_name": display_name,
                                "color_class": color_class,
                                "section": section  # Add section to each feature
                            })
                    
                # Normalize contributions to match total risk score, but preserve HTTPS percentage
                if result["feature_contributions"]:
                    # Sort by contribution (descending)
                    result["feature_contributions"].sort(key=lambda x: -x["percentage"])
                    
                    # Get total of all contributions
                    total_contribution = sum(item["percentage"] for item in result["feature_contributions"] 
                                           if item["name"] != "https_present")
                    https_contribution = next((item["percentage"] for item in result["feature_contributions"] 
                                             if item["name"] == "https_present"), 0)
                    
                    # Calculate what's left for other features
                    remaining_score = max(0, score - https_contribution)
                    
                    # If total is > 0, normalize the remaining features
                    if total_contribution > 0 and remaining_score > 0:
                        normalization_factor = remaining_score / total_contribution
                        for item in result["feature_contributions"]:
                            if item["name"] != "https_present":
                                item["percentage"] = round(item["percentage"] * normalization_factor, 1)
                    
                    # Calculate section totals based on fixed weights
                    # URL features (40%), Domain info (10%), Suspicious patterns (50%)
                    section_weights = {
                        "Key Risk Factors": 40.0,  # URL features (40%)
                        "Domain Information": 10.0,  # Domain information (10%)
                        "Suspicious Patterns": 50.0  # Suspicious patterns (50%)
                    }
                    
                    # Use fixed weights but distribute actual feature contributions within them
                    total_feature_impact = sum(item["percentage"] for item in result["feature_contributions"])
                    if total_feature_impact > 0:
                        # Normalize all feature impacts to a 0-100 scale
                        normalization_factor = score / total_feature_impact
                        for item in result["feature_contributions"]:
                            item["percentage"] = round(item["percentage"] * normalization_factor, 1)
                    
                    # Calculate actual section distribution based on feature categorization
                    actual_section_totals = {
                        "Key Risk Factors": 0,
                        "Domain Information": 0,
                        "Suspicious Patterns": 0
                    }
                    
                    for item in result["feature_contributions"]:
                        section = item["section"]
                        if section in actual_section_totals:
                            actual_section_totals[section] += item["percentage"]
                    
                    # Ensure the overall risk score is preserved 
                    result["section_totals"] = {
                        # Use fixed weights but make sure they sum to the overall score
                        "Key Risk Factors": round((section_weights["Key Risk Factors"] / 100) * score, 1),
                        "Domain Information": round((section_weights["Domain Information"] / 100) * score, 1),
                        "Suspicious Patterns": round((section_weights["Suspicious Patterns"] / 100) * score, 1)
                    }
                    
                # Get suspicious patterns
                suspicious_patterns = check_suspicious_patterns(url)
                result["suspicious_patterns"] = suspicious_patterns
                
                # Get domain information with more detail
                domain_info = get_domain_info(url)
                
                # Try to enhance domain info with more details if possible
                try:
                    # Parse URL to get domain
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    
                    # Try to get more domain info using socket
                    if not domain_info.get("organization"):
                        try:
                            ip = socket.gethostbyname(domain)
                            domain_info["ip_address"] = ip
                            
                            # Try to determine organization and location from IP
                            # Note: In a real implementation, you'd use a GeoIP service here
                            domain_info["organization"] = "Unknown Organization"
                            domain_info["country"] = "Unknown Country"
                            domain_info["city"] = "Unknown City"
                        except Exception as e:
                            logger.warning(f"Could not enhance domain info: {e}")
                except Exception as e:
                    logger.warning(f"Error enhancing domain info: {e}")
                
                result["domain_info"] = domain_info
                
                # Add HTML security data if available
                html_security = None
                try:
                    html_security = check_html_security(url)
                    result["html_security"] = html_security
                except Exception as e:
                    logger.error(f"Error checking HTML security: {e}")
                
                # Explicitly add feature_table for UI
                result['feature_table'] = []
                
                # Process features and organize by category
                for key, value in features.items():
                    if key != "error":
                        # Find the corresponding contribution
                        impact = 0.0
                        color_class = "success"
                        
                        for contrib in result["feature_contributions"]:
                            if contrib["name"] == key:
                                impact = contrib["percentage"]
                                color_class = contrib["color_class"]
                                break
                        
                        # Use friendly name if available
                        display_name = feature_name_map.get(key, key.replace("_", " ").title())
                        
                        # Always include HTTPS with fixed impact
                        if key == "https_present" and value < 1:
                            result['feature_table'].append({
                                'feature': "Security Weights",
                                'value': "No" if value < 1 else "Yes",
                                'impact': 24.6,  # Fixed percentage
                                'color_class': "danger"
                            })
                        # Only include features with significant impact or specifically important ones
                        elif impact > 3 or key in ["tld_score", "content_password_field_count", 
                                               "content_form_count", "html_security_score", 
                                               "domain_entropy", "content_favicon_exists", 
                                               "rep_domain_age_category"]:
                            # Format value based on type
                            formatted_value = value  # Default value
                            if isinstance(value, bool) or (isinstance(value, (int, float)) and value in [0, 1]):
                                formatted_value = "No" if value == 0 or value is False else "Yes"
                            elif isinstance(value, float) and value < 1:
                                formatted_value = round(value, 2)
                            
                            # Append to feature table
                            result['feature_table'].append({
                                'feature': display_name,
                                'value': formatted_value,
                                'impact': impact,
                                'color_class': color_class
                            })
                
                # Sort feature_table by impact (descending)
                result['feature_table'] = sorted(
                    result['feature_table'],
                    key=lambda x: -x['impact']
                )
                
                return result
                
            except Exception as e:
                logger.error(f"Error making prediction with model: {e}")
                logger.error(traceback.format_exc())
                # Fall back to rule-based prediction
                
        # Rule-based prediction (fallback)
        logger.info("Using rule-based prediction as fallback")
        return rule_based_prediction(url, features)
        
    except Exception as e:
        logger.error(f"Unexpected error in predict_with_model: {e}")
        logger.error(traceback.format_exc())
        return {
            "status": "error",
            "url": url,
            "message": f"Error making prediction: {str(e)}",
            "using_fallback": True,
            "score": 50,  # Default moderate risk
            "risk_level": "moderate",
            "domain_info": get_domain_info(url),
            "suspicious_patterns": check_suspicious_patterns(url)
        }

def get_risk_level(score):
    """
    Convert numerical risk score to categorical risk level
    
    Args:
        score: Numerical risk score (0-100)
        
    Returns:
        str: Risk level category
    """
    if score < 20:
        return "low"
    elif score < 50:
        return "moderate"
    elif score < 75:
        return "high"
    else:
        return "critical"

def get_domain_info(url):
    """
    Get information about a domain
    
    Args:
        url: URL to get domain info for
        
    Returns:
        dict: Domain information including IP, organization, location
    """
    try:
        # Parse the URL to extract domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Extract domain without port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Initialize domain info
        domain_info = {
            "domain": domain,
            "ip_address": "Unknown",
            "organization": "Unknown",
            "country": "Unknown",
            "city": "Unknown",
            "created": "Unknown",
            "expires": "Unknown",
            "latitude": 0,
            "longitude": 0
        }
        
        # Try to get IP address
        try:
            ip_address = socket.gethostbyname(domain)
            domain_info["ip_address"] = ip_address
            
            # Use ip-api.com for geolocation data
            try:
                geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get("status") == "success":
                        domain_info["country"] = geo_data.get("country", "Unknown")
                        domain_info["city"] = geo_data.get("city", "Unknown")
                        domain_info["latitude"] = geo_data.get("lat", 0)
                        domain_info["longitude"] = geo_data.get("lon", 0)
                        domain_info["organization"] = geo_data.get("org", "Unknown") or geo_data.get("isp", "Unknown")
                        domain_info["region"] = geo_data.get("regionName", "Unknown")
                        domain_info["timezone"] = geo_data.get("timezone", "Unknown")
                        domain_info["as"] = geo_data.get("as", "Unknown")
                        logger.info(f"Retrieved geolocation data for {ip_address}: {geo_data}")
                    else:
                        logger.warning(f"Failed to get geolocation data: {geo_data}")
                        # Fall back to default coordinates if geolocation fails
                        domain_info["latitude"] = 40.7128  # Default latitude (New York)
                        domain_info["longitude"] = -74.0060  # Default longitude (New York)
                else:
                    logger.warning(f"Failed to get geolocation data, status code: {geo_response.status_code}")
                    # Fall back to default coordinates if geolocation fails
                    domain_info["latitude"] = 40.7128
                    domain_info["longitude"] = -74.0060
            except Exception as geo_error:
                logger.error(f"Error getting geolocation data: {geo_error}")
                # Fall back to default coordinates if geolocation fails
                domain_info["latitude"] = 40.7128
                domain_info["longitude"] = -74.0060
                
        except socket.gaierror:
            domain_info["ip_address"] = "Could not resolve"
        
        return domain_info
        
    except Exception as e:
        logger.error(f"Error getting domain info: {e}")
        return {
            "domain": urlparse(url).netloc,
            "error": str(e),
            "ip_address": "Error",
            "organization": "Unknown",
            "country": "Unknown",
            "latitude": 0,
            "longitude": 0
        }

def check_ssl_certificate(domain):
    """
    Check SSL certificate information for a domain
    
    Args:
        domain: Domain to check SSL for
        
    Returns:
        dict: SSL certificate information
    """
    ssl_info = {
        "has_ssl": False,
        "issuer": "Unknown",
        "valid_from": "Unknown",
        "valid_until": "Unknown",
        "days_until_expiry": 0
    }
    
    try:
        # Try to connect with TLS/SSL
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate
                cert = ssock.getpeercert()
                ssl_info["has_ssl"] = True
                
                # Extract certificate details
                if cert:
                    # Get issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    ssl_info["issuer"] = issuer.get('organizationName', 'Unknown')
                    
                    # Get validity dates
                    ssl_info["valid_from"] = cert.get('notBefore', 'Unknown')
                    ssl_info["valid_until"] = cert.get('notAfter', 'Unknown')
                    
                    # Calculate days until expiry
                    if ssl_info["valid_until"] != 'Unknown':
                        expiry_date = datetime.strptime(ssl_info["valid_until"], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        ssl_info["days_until_expiry"] = max(0, days_until_expiry)
    except Exception as e:
        ssl_info["error"] = str(e)
    
    return ssl_info

def extract_whois_features(domain):
    """Extract features from WHOIS data for a domain"""
    whois_features = {
        "domain_age_days": 0,
        "expiration_remaining_days": 0,
        "recently_registered": 0,
        "privacy_protected": 0,
        "suspicious_registrar": 0
    }
    
    if not whois_available:
        return whois_features
    
    try:
        w = whois.whois(domain)
        
        # Calculate domain age
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
            whois_features["domain_age_days"] = domain_age
            whois_features["recently_registered"] = 1 if domain_age < 60 else 0
        
        # Calculate expiration time
        if w.expiration_date:
            expiry_date = w.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            days_until_expiry = (expiry_date - datetime.now()).days
            whois_features["expiration_remaining_days"] = max(0, days_until_expiry)
        
        # Check for privacy protection
        if w.registrar and "privacy" in str(w.registrar).lower():
            whois_features["privacy_protected"] = 1
            
        # Check for suspicious registrars
        suspicious_registrars = ["namecheap", "namesilo", "porkbun"]
        if w.registrar and any(r in str(w.registrar).lower() for r in suspicious_registrars):
            whois_features["suspicious_registrar"] = 1
            
        return whois_features
    except Exception as e:
        logger.error(f"Error getting WHOIS data: {e}")
        return whois_features

def extract_ct_log_features(domain):
    """Extract features from Certificate Transparency logs"""
    ct_features = {
        "cert_count": 0,
        "recent_cert_count": 0,
        "suspicious_cert_pattern": 0
    }
    
    try:
        # Use crt.sh API to check certificate history
        response = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=5)
        if response.status_code == 200:
            try:
                certs = response.json()
                
                # Total certificates
                ct_features["cert_count"] = len(certs)
                
                # Recent certificates (last 30 days)
                thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
                recent_certs = [c for c in certs if c.get("not_before", "") > thirty_days_ago]
                ct_features["recent_cert_count"] = len(recent_certs)
                
                # Check for suspicious patterns in certificate names
                for cert in certs:
                    common_name = cert.get("common_name", "").lower()
                    if any(p in common_name for p in ["secure", "login", "banking", "verify"]):
                        ct_features["suspicious_cert_pattern"] = 1
                        break
            except json.JSONDecodeError:
                logger.warning("Failed to parse certificate data as JSON")
                    
        return ct_features
    except Exception as e:
        logger.error(f"Error getting certificate data: {e}")
        return ct_features

def extract_content_features(url, html_content=None):
    """Extract features from webpage content"""
    content_features = {
        "page_size_bytes": 0,
        "external_resources_count": 0,
        "form_count": 0,
        "password_field_count": 0,
        "js_to_html_ratio": 0,
        "title_brand_mismatch": 0,
        "favicon_exists": 0,
        "similar_domain_redirect": 0
    }
    
    if not BeautifulSoup_available:
        return content_features
        
    try:
        # Get the HTML content if not provided
        if html_content is None:
            try:
                response = requests.get(url, timeout=10, 
                                     headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                html_content = response.text
                content_features["page_size_bytes"] = len(html_content)
            except Exception as req_error:
                logger.error(f"Error fetching HTML content: {req_error}")
                return content_features
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Count forms and password fields
        content_features["form_count"] = len(soup.find_all("form"))
        content_features["password_field_count"] = len(soup.find_all("input", {"type": "password"}))
        
        # External resources
        external_resources = 0
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc
        
        for tag in soup.find_all(["script", "img", "iframe", "link"], src=True):
            src = tag.get("src", "")
            if src and not src.startswith(('/', '#', 'data:')):
                if base_domain not in src:
                    external_resources += 1
                    
        for tag in soup.find_all("link", href=True):
            href = tag.get("href", "")
            if href and not href.startswith(('/', '#', 'data:')):
                if base_domain not in href:
                    external_resources += 1
                    
        content_features["external_resources_count"] = external_resources
        
        # JS to HTML ratio
        js_content = 0
        for script in soup.find_all("script"):
            if script.string:
                js_content += len(script.string)
        
        if len(html_content) > 0:
            content_features["js_to_html_ratio"] = js_content / len(html_content)
            
        # Title brand mismatch
        if soup.title and soup.title.string:
            title = soup.title.string.lower()
            domain_parts = base_domain.lower().split(".")
            brand_name = domain_parts[0] if domain_parts[0] != "www" else domain_parts[1]
            
            if title and brand_name not in title:
                content_features["title_brand_mismatch"] = 1
            
        # Check for favicon
        if soup.find("link", rel="icon") or soup.find("link", rel="shortcut icon"):
            content_features["favicon_exists"] = 1
            
        # Check for redirects to similar domains
        meta_refresh = soup.find("meta", {"http-equiv": "refresh"})
        if meta_refresh and "content" in meta_refresh.attrs:
            content = meta_refresh["content"]
            if "url=" in content.lower():
                redirect_url = content.split("url=")[1].strip()
                redirect_domain = urlparse(redirect_url).netloc
                
                # Check if redirect domain is similar but different
                similarity = SequenceMatcher(None, base_domain, redirect_domain).ratio()
                if 0.6 < similarity < 0.9:  # Similar but not identical
                    content_features["similar_domain_redirect"] = 1
        
        return content_features
    except Exception as e:
        logger.error(f"Error extracting content features: {e}")
        return content_features

def extract_nlp_features(domain):
    """Extract NLP-based features from the domain name"""
    nlp_features = {
        "character_distribution": 0,
        "vowel_consonant_ratio": 0,
        "contains_digits": 0,
        "contains_repeated_chars": 0,
        "ngram_score": 0,
        "word_length_avg": 0
        }
    
    try:
        # Remove TLD for analysis
        domain_parts = domain.split('.')
        domain_without_tld = '.'.join(domain_parts[:-1]) if len(domain_parts) > 1 else domain_parts[0]
        
        # Character distribution (normalized entropy)
        entropy = calculate_entropy(domain_without_tld)
        nlp_features["character_distribution"] = entropy / 4.7  # Normalize, 4.7 is max entropy for English text
        
        # Vowel to consonant ratio
        vowels = sum(c.lower() in 'aeiou' for c in domain_without_tld)
        consonants = sum(c.lower() in 'bcdfghjklmnpqrstvwxyz' for c in domain_without_tld)
        nlp_features["vowel_consonant_ratio"] = vowels / consonants if consonants > 0 else 0
        
        # Contains digits
        nlp_features["contains_digits"] = 1 if any(c.isdigit() for c in domain_without_tld) else 0
        
        # Contains repeated characters (3 or more)
        if re.search(r'(.)\1{2,}', domain_without_tld):
            nlp_features["contains_repeated_chars"] = 1
            
        # N-gram probability score (approximated)
        common_english_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or"]
        bigram_count = sum(domain_without_tld.lower().count(bigram) for bigram in common_english_bigrams)
        domain_length = len(domain_without_tld)
        nlp_features["ngram_score"] = bigram_count / (domain_length - 1) if domain_length > 1 else 0
        
        # Average word length if domain has words
        words = re.findall(r'[a-zA-Z]+', domain_without_tld)
        if words:
            avg_word_length = sum(len(word) for word in words) / len(words)
            nlp_features["word_length_avg"] = avg_word_length
            
        return nlp_features
    except Exception as e:
        logger.error(f"Error extracting NLP features: {e}")
        return nlp_features

def extract_reputation_features(domain, ip_address):
    """Extract reputation-based features from various sources"""
    reputation_features = {
        "domain_age_category": 0,  # 0: unknown, 1: new, 2: medium, 3: established
        "ip_blacklisted": 0,
        "domain_blacklisted": 0,
        "suspicious_tld_category": 0,
        "suspicious_country": 0
    }
    
    try:
        # Domain age categorization (if whois is available)
        if whois_available:
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    domain_age_days = (datetime.now() - creation_date).days
                    
                    if domain_age_days < 30:
                        reputation_features["domain_age_category"] = 1  # New
                    elif domain_age_days < 180:
                        reputation_features["domain_age_category"] = 2  # Medium
                    else:
                        reputation_features["domain_age_category"] = 3  # Established
            except Exception as whois_error:
                logger.warning(f"Whois error for reputation features: {whois_error}")
            
        # Check for blacklisted IP (simplified - would use an actual API)
        high_risk_countries = ["RU", "CN", "IR", "KP", "NG"]
        suspicious_asn_orgs = ["Cloudflare", "OVH", "DigitalOcean", "Amazon"]
        
        # Get IP geolocation
        if ip_address and ip_address != "Unknown" and ip_address != "Could not resolve":
            try:
                geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get("status") == "success":
                        # Check country risk
                        if geo_data.get("countryCode") in high_risk_countries:
                            reputation_features["suspicious_country"] = 1
                        
                        # Check ASN risk
                        asn_org = geo_data.get("org", "").lower()
                        if any(org.lower() in asn_org for org in suspicious_asn_orgs):
                            reputation_features["ip_blacklisted"] = 0.5  # Partial flag
            except Exception as geo_error:
                logger.warning(f"Error getting geolocation for reputation: {geo_error}")
                
        # Check TLD risk category
        tld = domain.split('.')[-1] if '.' in domain else ''
        high_risk_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'icu', 'rest', 'zip']
        medium_risk_tlds = ['online', 'site', 'club', 'live', 'vip', 'fit', 'pw']
        
        if tld in high_risk_tlds:
            reputation_features["suspicious_tld_category"] = 2
        elif tld in medium_risk_tlds:
            reputation_features["suspicious_tld_category"] = 1
            
        return reputation_features
    except Exception as e:
        logger.error(f"Error extracting reputation features: {e}")
        return reputation_features

def analyze_url(url):
    """
    Comprehensive URL analysis function that combines multiple checks
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: Comprehensive analysis result
    """
    logger.info(f"Analyzing URL: {url}")
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        logger.info(f"Added scheme to URL: {url}")
    
    try:
        # Extract features and make prediction
        features, feature_vector = extract_features(url)
        prediction_result = predict_with_model(url)
        
        # Get suspicious patterns
        suspicious_patterns = check_suspicious_patterns(url)
        
        # Check HTML security
        html_security = check_html_security(url)
        
        # Parse URL components for display
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        scheme = parsed_url.scheme
        
        # Get domain information if available
        domain_info = get_domain_info(url)
        
        # Create comprehensive analysis result
        result = {
            "status": "success",
            "url": url,
            "domain": domain,
            "protocol": scheme,
            "analysis_date": datetime.now().isoformat(),
            "score": prediction_result.get("score", 0),
            "fraud_score": prediction_result.get("score", 0),  # Duplicate for UI compatibility
            "risk_level": prediction_result.get("risk_level", "unknown"),
            "is_suspicious": prediction_result.get("score", 0) > 50,
            "suspicious_patterns": suspicious_patterns,
            "html_security": html_security,
            "risk_factors": prediction_result.get("risk_factors", {}),
            "feature_values": features,
            "domain_info": domain_info,
            "feature_contributions": prediction_result.get("feature_contributions", []),
            "feature_table": prediction_result.get("feature_table", []),
            "section_totals": prediction_result.get("section_totals", {})
        }
        
        # Ensure section totals are set using fixed weights if missing
        if not result["section_totals"]:
            score = result["score"]
            result["section_totals"] = {
                "Key Risk Factors": round(0.4 * score, 1),  # URL features (40%)
                "Domain Information": round(0.1 * score, 1),  # Domain information (10%)
                "Suspicious Patterns": round(0.5 * score, 1)  # Suspicious patterns + HTML content (50%)
            }
        
        # Special handling for trusted domains - reduce Suspicious Patterns section score
        # when no actual suspicious patterns were found
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # If no suspicious patterns were found, set that section to 0%
        # regardless of whether it's a trusted domain or not
        if not suspicious_patterns:
            # Set Suspicious Patterns to 0% since none were found
            original_suspicious_patterns_score = result["section_totals"]["Suspicious Patterns"]
            result["section_totals"]["Suspicious Patterns"] = 0.0
            
            # Recalculate overall score by removing the suspicious patterns contribution
            original_score = result["score"]
            
            # When Suspicious Patterns is set to 0, recalculate the total score
            # by considering only the remaining sections (Key Risk Factors + Domain Information)
            key_risk_score = result["section_totals"]["Key Risk Factors"]
            domain_info_score = result["section_totals"]["Domain Information"]
            
            # Set the adjusted score to be just the sum of the remaining sections
            adjusted_score = key_risk_score + domain_info_score
            
            # Update the overall score
            result["score"] = adjusted_score
            result["fraud_score"] = adjusted_score
            result["risk_level"] = get_risk_level(adjusted_score)
            logger.info(f"Adjusted score due to no suspicious patterns: {original_score} -> {adjusted_score}")
        
        # Add SSL info if available
        try:
            ssl_info = check_ssl_certificate(domain)
            result["ssl_info"] = ssl_info
        except Exception as e:
            logger.warning(f"Unable to check SSL certificate: {str(e)}")
            result["ssl_info"] = {"error": str(e)}
        
        logger.info(f"Analysis complete for {url} - Risk score: {result['score']}")
        return result
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "status": "error",
            "url": url,
            "message": f"Error analyzing URL: {str(e)}",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "domain_info": get_domain_info(url),
            "suspicious_patterns": check_suspicious_patterns(url)
        }

@app.route("/")
@app.route("/index.html")
def home():
    logger.info("Home route accessed")
    try:
        return render_template("index.html")
    except Exception as e:
        logger.error(f"Error rendering index.html: {e}")
        return f"Error: {str(e)}", 500

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/health-check")
def health_check():
    """Health check endpoint for the integrated application"""
    return jsonify({
        "status": "healthy",
        "message": "Integrated Flask app is running",
        "model_loaded": get_model_instance() is not None,
        "scaler_loaded": get_scaler_instance() is not None
    })

@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'success'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
    
    if request.method == 'POST':
        try:
            # Log request headers for debugging
            logger.info(f"Request headers: {dict(request.headers)}")
            logger.info(f"Request content type: {request.content_type}")
            logger.info(f"Raw request data: {request.data.decode('utf-8', errors='replace') if request.data else 'None'}")
            
            # Extract URL from request
            url = None
            
            # Try different methods to extract the URL
            if request.is_json:
                data = request.get_json(force=True)
                logger.info(f"JSON data: {data}")
                url = data.get('url', '')
            elif request.form:
                logger.info(f"Form data: {dict(request.form)}")
                url = request.form.get('url', '')
            elif request.data:
                try:
                    data = json.loads(request.data.decode('utf-8'))
                    logger.info(f"Parsed JSON from raw data: {data}")
                    url = data.get('url', '')
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse raw data as JSON: {e}")
            
            logger.info(f"Extracted URL: {url}")
            
            if not url or len(url.strip()) == 0:
                logger.error("No URL provided in request")
                return jsonify({
                    "status": "error", 
                    "message": "No URL provided", 
                    "details": "Please enter a valid URL to analyze"
                }), 400
            
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                logger.info(f"Added http:// prefix to URL: {url}")
            
            # Process the URL directly without backend API call
            logger.info("Processing prediction request directly")
            
            # Extract features
            features, feature_vector = extract_features(url)
            
            # Get prediction
            result = predict_with_model(url, features)
            
            # Save to Firestore history if user is authenticated
            user_id = get_user_id_from_request(request)
            if user_id:
                save_history_to_firestore(user_id, url, result)
            
            # For debugging the feature display issue
            logger.info(f"Feature contributions: {result.get('feature_contributions', [])}")
            
            # Explicitly add this field for the UI
            if 'feature_table' not in result:
                result['feature_table'] = []
                # Add entries to feature_table if feature_contributions exists
                if 'feature_contributions' in result and result['feature_contributions']:
                    for contrib in result['feature_contributions']:
                        result['feature_table'].append({
                            'feature': contrib['name'],
                            'value': contrib['value'],
                            'impact': contrib['contribution'] * 100  # Convert to percentage
                        })
                    
                    # Sort feature_table: non-zero values in ascending order, zero values at the bottom
                    result['feature_table'] = sorted(
                        result['feature_table'],
                        key=lambda x: (x['value'] == 0, x['value'])
                    )
            
            logger.info(f"Feature table: {result.get('feature_table', [])}")
            logger.info(f"Prediction result: {result}")
            return jsonify(result)
        except Exception as e:
            logger.error(f"Unexpected error in predict route: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "status": "error",
                "message": "An unexpected error occurred",
                "details": str(e)
            }), 500

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Render the login page with Firebase authentication"""
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Render the registration page with Firebase authentication"""
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Handle logout - with Firebase this is client-side"""
    # Clear any server-side session data
    session.clear()
    # The actual logout happens on the client side with Firebase
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    """User dashboard page - protected by Firebase auth on client side"""
    return render_template('dashboard.html')

@app.route("/analyze", methods=['GET', 'POST', 'OPTIONS'])
def analyze():
    """
    Generate analysis report for a URL.
    Forward the request to the backend instead of handling it directly.
    """
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'success'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
    
    # Get the requested format (pdf or json)
    report_format = request.args.get('format', '').lower()
    
    # Extract URL from request
    url = None
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json(force=True)
            url = data.get('url', '')
        elif request.form:
            url = request.form.get('url', '')
        elif request.data:
            try:
                data = json.loads(request.data.decode('utf-8'))
                url = data.get('url', '')
            except json.JSONDecodeError:
                pass
    else:  # GET request
        url = request.args.get('url', '')
    
    if not url or len(url.strip()) == 0:
        return jsonify({
            "status": "error", 
            "message": "No URL provided", 
            "details": "Please enter a valid URL to analyze"
        }), 400
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Forward the request to the backend API
        backend_url = os.environ.get('BACKEND_URL', 'http://localhost:5000').rstrip('/') + '/analyze'
        
        # Prepare the request parameters
        params = {}
        if report_format:
            params['format'] = report_format
            
        # Send the request to the backend
        logger.info(f"Forwarding analyze request to backend: {backend_url}")
            
        if request.method == 'POST':
            response = requests.post(
                backend_url,
                json={"url": url},
                params=params,
                headers={"Content-Type": "application/json"}
            )
        else:  # GET request
            response = requests.get(
                backend_url,
                params={"url": url, **params}
            )
            
        # Check if the response was successful
        if response.status_code == 200:
            # Try to parse the response as JSON
            try:
                result = response.json()
                # Save to Firestore history if user is authenticated
                user_id = get_user_id_from_request(request)
                if user_id:
                    save_history_to_firestore(user_id, url, result)
                return jsonify(result)
            except:
                # If we couldn't parse as JSON, return the raw response
                return response.text, 200, {'Content-Type': 'text/html'}
        else:
            # If the backend returned an error, log it and fall back to local analysis
            logger.warning(f"Backend returned error {response.status_code}: {response.text}")
            logger.info("Using local analysis as fallback")
            
            # Fall back to local implementation using analyze_url
            analysis_result = analyze_url(url)
            # Save to Firestore history if user is authenticated
            user_id = get_user_id_from_request(request)
            if user_id:
                save_history_to_firestore(user_id, url, analysis_result)
            return jsonify(analysis_result)
            
    except requests.RequestException as e:
        logger.error(f"Error connecting to backend API: {e}")
        logger.info("Using local analysis as fallback")
        
        # Fall back to local implementation using analyze_url
        analysis_result = analyze_url(url)
        # Save to Firestore history if user is authenticated
        user_id = get_user_id_from_request(request)
        if user_id:
            save_history_to_firestore(user_id, url, analysis_result)
        return jsonify(analysis_result)
        
    except Exception as e:
        logger.error(f"Error generating analysis: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error", 
            "message": "Failed to generate analysis",
            "details": str(e)
        }), 500

@app.route("/test")
def test():
    """Test route to verify the Flask app is running properly"""
    return jsonify({
        "status": "success",
        "message": "Integrated Flask app is running successfully!",
        "model_loaded": get_model_instance() is not None,
        "scaler_loaded": get_scaler_instance() is not None
    })

@app.route('/diagnostic')
def diagnostic_page():
    """Serve the diagnostic page to test functionality"""
    return render_template('diagnostic.html')

@app.route('/model-status', methods=['GET'])
def model_status():
    """Check the status of the model"""
    status = {
        "model_loaded": get_model_instance() is not None,
        "scaler_loaded": get_scaler_instance() is not None,
        "status": "operational" if get_model_instance() is not None and get_scaler_instance() is not None else "error",
        "model_type": str(type(get_model_instance())) if get_model_instance() else "None",
        "using_fallback": hasattr(get_model_instance(), 'summary') and get_model_instance().summary() == "Fallback model (SimpleModel)"
    }
    return jsonify(status)

@app.route('/debug', methods=['GET'])
def debug():
    """Debug endpoint showing environment and configuration"""
    debug_info = {
        "environment": {k: v for k, v in os.environ.items() if not k.startswith("_") and not "TOKEN" in k and not "SECRET" in k},
        "model_path": os.environ.get('MODEL_FILE', 'models/fraud_detection_model.h5'),
        "model_loaded": get_model_instance() is not None,
        "scaler_loaded": get_scaler_instance() is not None,
        "model_type": str(type(get_model_instance())) if get_model_instance() else "None"
    }
    return jsonify(debug_info)

# Function to fix dtype policy in model config
def fix_dtype_policy(config):
    """Fix issues with DTypePolicy deserialization"""
    if isinstance(config, dict):
        # Replace dtype objects with string representation
        if 'dtype' in config and isinstance(config['dtype'], dict) and config['dtype'].get('class_name') == 'DTypePolicy':
            config['dtype'] = 'float32'
        
        # Recursively process nested configs
        for key, value in config.items():
            if isinstance(value, dict):
                config[key] = fix_dtype_policy(value)
            elif isinstance(value, list):
                config[key] = [fix_dtype_policy(item) if isinstance(item, (dict, list)) else item for item in value]
    
    elif isinstance(config, list):
        config = [fix_dtype_policy(item) if isinstance(item, (dict, list)) else item for item in config]
    
    return config

def safe_decode_model_config(raw_config):
    """Safely decode model configuration to handle any version compatibility issues."""
    try:
        # Parse the raw model config
        config = json.loads(raw_config)
        
        # Apply fixes to the config
        config = fix_dtype_policy(config)
        
        # Re-encode as JSON string
        return json.dumps(config)
    except Exception as e:
        logger.error(f"Error processing model config: {e}")
        # Return original if processing failed
        return raw_config

def build_compatible_model(model_path):
    """Build a compatible model manually from the H5 file."""
    try:
        # Open the H5 file
        with h5py.File(model_path, 'r') as h5file:
            # Check if the model config exists
            if 'model_config' in h5file.attrs:
                # Get the model config as a JSON string
                model_config = h5file.attrs['model_config']
                
                # Fix compatibility issues in the config
                fixed_config = safe_decode_model_config(model_config)
                
                # Create a model from the fixed config
                model = tf.keras.models.model_from_json(
                    fixed_config,
                    custom_objects={
                        'InputLayer': CompatibleInputLayer,
                        'FairnessConstraint': tf.keras.constraints.UnitNorm,
                        'FairnessPenalty': tf.keras.layers.Layer
                    }
                )
                
                # Load weights
                model.load_weights(model_path)
                
                logger.info("Built compatible model manually from H5 file")
                return model
            else:
                logger.error("No model config found in H5 file")
                return None
    except Exception as e:
        logger.error(f"Error building compatible model: {e}")
        return None

@app.route('/debug-connection', methods=['GET', 'POST'])
def debug_connection():
    """Debugging endpoint for connection issues"""
    try:
        if request.method == 'POST':
            # Echo back the request data
            data = request.get_json() if request.is_json else {}
            
            # Add additional debugging info
            response_data = {
                "status": "success",
                "message": "Connection is working",
                "timestamp": datetime.now().isoformat(),
                "request_data": data,
                "request_headers": dict(request.headers),
                "content_type": request.content_type,
                "method": request.method,
                "environment": {
                    "python_version": sys.version,
                    "flask_version": flask.__version__,
                    "tensorflow_version": tf.__version__
                }
            }
            
            return jsonify(response_data)
        else:
            # Simple GET response for connection testing
            return jsonify({
                "status": "success",
                "message": "Connection is working",
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"Error in debug-connection endpoint: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/analyzer')
def analyzer():
    """Redirect to home page with any URL query parameter"""
    url = request.args.get('url', '')
    if url:
        return redirect(f'/?url={url}')
    return redirect('/')

@app.route('/history')
def history():
    # Always render the history page; frontend JS will handle auth and data
    return render_template('history.html')

@app.route('/profile')
def profile():
    """User profile page - protected by Firebase auth on client side"""
    return render_template('profile.html')

@app.route('/api/analyze-url', methods=['POST', 'OPTIONS'])
def api_analyze_url():
    """API endpoint for analyzing URLs - specifically for the dashboard Quick URL Analyzer"""
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'success'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        return response
    
    if request.method == 'POST':
        try:
            # Log request details for debugging
            logger.info(f"API analyze-url request received")
            
            # Extract URL from request
            url = None
            data = None
            
            if request.is_json:
                data = request.get_json(force=True)
                logger.info(f"JSON data: {data}")
                url = data.get('url', '')
            elif request.form:
                logger.info(f"Form data: {dict(request.form)}")
                url = request.form.get('url', '')
            elif request.data:
                try:
                    data = json.loads(request.data.decode('utf-8'))
                    logger.info(f"Parsed JSON from raw data: {data}")
                    url = data.get('url', '')
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse raw data as JSON: {e}")
            
            logger.info(f"Extracted URL for analysis: {url}")
            
            if not url or len(url.strip()) == 0:
                logger.error("No URL provided in request")
                return jsonify({
                    "status": "error", 
                    "message": "No URL provided", 
                    "details": "Please enter a valid URL to analyze"
                }), 400
            
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                logger.info(f"Added http:// prefix to URL: {url}")
            
            # Process the URL using the analyze_url function
            logger.info(f"Analyzing URL: {url}")
            
            # Call analyze_url to get complete analysis
            analysis_result = analyze_url(url)
            
            # Save to Firestore history if user is authenticated
            user_id = get_user_id_from_request(request)
            if user_id:
                save_history_to_firestore(user_id, url, analysis_result)
            
            logger.info(f"Analysis complete for {url}")
            return jsonify(analysis_result)
            
        except Exception as e:
            logger.error(f"Error in API analyze-url: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "status": "error",
                "message": "An error occurred while analyzing the URL",
                "details": str(e)
            }), 500

if firebase_available:
    from firebase_admin import firestore
    db = firestore.client()
else:
    db = None

def save_history_to_firestore(user_id, url, result):
    if not db:
        logger.warning("Firestore not available, cannot save history")
        return
    try:
        # Save to the same path the frontend expects
        doc_ref = db.collection('users').document(user_id).collection('scans').document()
        doc_ref.set({
            'url': url,
            'result': result,
            'timestamp': datetime.utcnow()
        })
        logger.info(f"Saved analysis for {url} to history for user {user_id}")
    except Exception as e:
        logger.error(f"Error saving history to Firestore: {e}")

def get_user_id_from_request(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    id_token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token['uid']
    except Exception as e:
        logger.error(f"Invalid Firebase ID token: {e}")
        return None

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    logger.info(f"Starting application on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
