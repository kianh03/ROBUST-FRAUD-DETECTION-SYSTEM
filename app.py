import numpy as np
import tensorflow as tf
import joblib
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from urllib.parse import urlparse, parse_qs
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
import json
import os
import tldextract
import socket
from urllib.request import urlopen
from datetime import datetime, timedelta
import requests
from collections import Counter
import ipaddress
import geocoder
from bs4 import BeautifulSoup
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Use TF version compatibility
if hasattr(tf.keras, "saving"):
    register_serializable = tf.keras.saving.register_keras_serializable
else:
    register_serializable = tf.keras.utils.register_keras_serializable

# 1. Custom Components - Need to define the same custom classes here for loading
@register_serializable(package="FraudDetection")
class FairnessConstraint(tf.keras.constraints.Constraint):
    def __init__(self, max_influence=0.3):
        self.max_influence = max_influence
        
    def __call__(self, w):
        return tf.clip_by_value(w, -self.max_influence, self.max_influence)
    
    def get_config(self):
        return {'max_influence': self.max_influence}

@register_serializable(package="FraudDetection")
class FairnessPenalty(tf.keras.layers.Layer):
    def __init__(self, **kwargs):
        super(FairnessPenalty, self).__init__(**kwargs)
    
    def call(self, inputs):
        y_pred, features = inputs
        protocol = features[:, 4]
        http_mask = tf.cast(protocol < 0.5, tf.float32)
        http_mean = tf.reduce_mean(y_pred * http_mask)
        https_mean = tf.reduce_mean(y_pred * (1 - http_mask))
        penalty = tf.abs(http_mean - https_mean)
        self.add_loss(0.5 * penalty)
        return y_pred
    
    def get_config(self):
        config = super(FairnessPenalty, self).get_config()
        return config

# Define custom objects dictionary for model loading
CUSTOM_OBJECTS = {
    'FairnessConstraint': FairnessConstraint,
    'FairnessPenalty': FairnessPenalty
}

MODEL_PATH = "fraud_model.h5"
TOKENIZER_PATH = "tokenizer.pkl"
SCALER_PATH = "scaler.pkl"
MAX_LEN = 200

# Cached data
DOMAIN_TRUST_CACHE = {}
DOMAIN_CATEGORY_CACHE = {}
DOMAIN_INFO_CACHE = {}
IP_GEOLOCATION_CACHE = {}

# Trusted TLDs - top-level domains that are generally more regulated or restricted
TRUSTED_TLDS = {
    'gov', 'edu', 'mil',  # US government, education, and military
    'uk', 'ca', 'au', 'nz', 'jp', 'fr', 'de', 'it', 'es', 'dk', 'ch', 'se', 'no', 'fi', 'ie', 'nl',  # Major country codes with regulation
    'museum', 'post', 'int', 'aero', 'coop', 'name', 'jobs', 'travel'  # Regulated specialized domains
}

# Known URL shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 
    'adf.ly', 'j.mp', 'bitly.com', 'cur.lv', 'cutt.ly', 'tiny.cc', 'rebrand.ly',
}

# Domain categories for classification
DOMAIN_CATEGORIES = {
    'technology': ['tech', 'software', 'hardware', 'cloud', 'data', 'hosting', 'app', 'device'],
    'search_engine': ['search', 'google', 'bing', 'yahoo', 'baidu', 'yandex', 'duckduckgo'],
    'social_media': ['social', 'community', 'connect', 'network', 'share', 'follow', 'friend', 'post', 'like'],
    'ecommerce': ['shop', 'store', 'buy', 'sell', 'market', 'price', 'deal', 'discount', 'order', 'shipping'],
    'news': ['news', 'journal', 'times', 'daily', 'post', 'herald', 'tribune', 'gazette', 'press'],
    'education': ['edu', 'learn', 'course', 'class', 'school', 'college', 'university', 'academy', 'training'],
    'finance': ['bank', 'finance', 'money', 'invest', 'loan', 'credit', 'insurance', 'pay', 'tax'],
    'healthcare': ['health', 'medical', 'doctor', 'hospital', 'clinic', 'care', 'patient', 'therapy', 'wellness'],
    'government': ['gov', 'government', 'state', 'federal', 'county', 'city', 'agency', 'department', 'official'],
    'entertainment': ['entertainment', 'game', 'play', 'fun', 'movie', 'film', 'music', 'video', 'stream', 'theater'],
    'travel': ['travel', 'trip', 'tour', 'hotel', 'flight', 'vacation', 'booking', 'reservation', 'destination'],
    'ai': ['ai', 'ml', 'gpt', 'chat', 'bot', 'intelligence', 'neural', 'model', 'cognitive', 'learning']
}

# Regular expressions for detecting suspicious URL patterns
SUSPICIOUS_PATTERNS = {
    r'(login|signin|account|verify|secure|auth|confirm|update|password).*\.(php|html)': 'Login or account verification page with suspicious extension',
    r'(paypal|apple|microsoft|amazon|google|facebook|instagram|netflix).*\.(com|net|org).*(?!.*\.(com|net|org))': 'Brand name followed by another domain extension',
    r'(payment|verify|confirm|secure|auth).*\?.*token': 'Authentication or verification with token parameter',
    r'.*[0o][l1][a@4][h8].*': 'Potential character substitution (common in phishing)',
    r'.*\.tk\/': 'Free TLD domain (.tk) often used for phishing',
    r'.*-?secur(e|ity)-?.*': 'Security-related terms often used in phishing',
    r'.*@.*': 'URL with @ symbol (can be used for deception)',
    r'.*[a-zA-Z0-9]{25,}.*': 'Unusually long string in URL (could be obfuscation)',
    r'.*\d{10,}.*': 'Unusually long numeric sequence in URL',
    r'.*(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd)\/.*': 'URL shortener service (can mask malicious destinations)',
    r'.*[^\w.-]password[^\w.-].*': 'Contains the word "password" (common in phishing)',
    r'.*[^\w.-]credit[-_]?card[^\w.-].*': 'Contains phrase related to credit card',
    r'.*[^\w.-]bank[^\w.-].*': 'Contains banking related words',
    r'.*(\.php\?id=|\.aspx\?id=|\.jsp\?id=).*': 'Script with ID parameter (common in phishing)',
    r'.*\.(info|xyz|top|club|online|site)\/.*': 'Low-cost TLDs commonly abused',
    r'.*[^\w.-](free|gratis)[^\w.-].*': 'Free offer promotions (common in scams)',
    r'.*[^\w.-](alert|warning|urgent|important)[^\w.-].*': 'Urgency words (common in phishing)',
    r'.*[^\w.-]crypto[^\w.-].*': 'Cryptocurrency mentions (common in scams)',
    r'.*[^\w.-]bitcoin[^\w.-].*': 'Bitcoin mentions (common in scams)',
    r'.*\/[^\/]{80,}': 'Extremely long path segment (potential obfuscation)',
}

# List of known trusted domains
TRUSTED_DOMAINS = {
    'google.com': {'category': 'technology', 'display': 'Search Engine'},
    'apple.com': {'category': 'technology', 'display': 'Tech Company'},
    'microsoft.com': {'category': 'technology', 'display': 'Tech Company'},
    'amazon.com': {'category': 'shopping', 'display': 'E-commerce'},
    'facebook.com': {'category': 'social_media', 'display': 'Social Media'},
    'instagram.com': {'category': 'social_media', 'display': 'Social Media'},
    'twitter.com': {'category': 'social_media', 'display': 'Social Media'},
    'linkedin.com': {'category': 'social_media', 'display': 'Professional Network'},
    'github.com': {'category': 'technology', 'display': 'Code Repository'},
    'youtube.com': {'category': 'social_media', 'display': 'Video Platform'},
    'netflix.com': {'category': 'entertainment', 'display': 'Streaming Service'},
    'paypal.com': {'category': 'financial', 'display': 'Payment Service'},
    'wikipedia.org': {'category': 'education', 'display': 'Encyclopedia'},
    'openai.com': {'category': 'ai', 'display': 'AI Platform'},
    'claude.ai': {'category': 'ai', 'display': 'AI Assistant'},
    'anthropic.com': {'category': 'ai', 'display': 'AI Company'},
    'bard.google.com': {'category': 'ai', 'display': 'AI Assistant'},
    'bing.com': {'category': 'technology', 'display': 'Search Engine'},
    'chatgpt.com': {'category': 'ai', 'display': 'AI Platform'},
    'nasa.gov': {'category': 'government', 'display': 'Government Agency'},
    'nih.gov': {'category': 'government', 'display': 'Government Agency'},
    'edu': {'category': 'education', 'display': 'Education Domain'},
    'gov': {'category': 'government', 'display': 'Government Domain'},
    'mil': {'category': 'government', 'display': 'Military Domain'},
}

# Load model with custom objects
try:
    print("Loading model with custom objects...")
    model = tf.keras.models.load_model(MODEL_PATH, custom_objects=CUSTOM_OBJECTS)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    print("Trying an alternative approach...")
    # Alternative approach for some TF versions
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
    except Exception as e2:
        print(f"Alternative loading also failed: {str(e2)}")
        raise

# Load tokenizer and scaler
tokenizer = joblib.load(TOKENIZER_PATH)
scaler = joblib.load(SCALER_PATH)

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create database tables
with app.app_context():
    db.create_all()

def calculate_entropy(s):
    if len(s) == 0: return 0.0
    p, lns = np.unique(list(s), return_counts=True)
    return -np.sum((lns/len(s)) * np.log2(lns/len(s)))

def tld_risk_score(tld):
    # Updated to match training code
    risky_tlds = {
        'xyz': 0.7, 'top': 0.65, 'loan': 0.85, 'bid': 0.8, 
        'online': 0.75, 'site': 0.7, 'club': 0.65, 'stream': 0.8,
        'icu': 0.75, 'live': 0.6, 'vip': 0.7, 'fit': 0.6,
        'tk': 0.8, 'ml': 0.75, 'ga': 0.75, 'cf': 0.7
    }
    return risky_tlds.get(tld.lower(), 0.2)

def get_ip_address(domain):
    """Get IP address for a domain"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_ip_geolocation(ip):
    """Get geolocation info for an IP address"""
    if ip in IP_GEOLOCATION_CACHE:
        return IP_GEOLOCATION_CACHE[ip]
    
    try:
        # First try using the geocoder library
        g = geocoder.ip(ip)
        if g.ok:
            result = {
                'country': g.country or "Unknown",
                'region': g.state or "Unknown",
                'city': g.city or "Unknown",
                'org': g.org or "Unknown",
                'lat': g.lat,
                'lng': g.lng
            }
            IP_GEOLOCATION_CACHE[ip] = result
            return result
    except Exception as e:
        print(f"Geocoder error: {str(e)}")
        
    try:
        # Fallback to ipinfo.io if geocoder fails
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        if response.status_code == 200:
            data = response.json()
            result = {
                'country': data.get('country', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'lat': None,
                'lng': None
            }
            
            # Try to parse coordinates if available
            if 'loc' in data and ',' in data['loc']:
                try:
                    lat, lng = data['loc'].split(',')
                    result['lat'] = float(lat)
                    result['lng'] = float(lng)
                except:
                    pass
                
            IP_GEOLOCATION_CACHE[ip] = result
            return result
    except Exception as e:
        print(f"IPInfo error: {str(e)}")
    
    # Default response if all APIs fail
    default = {
        'country': 'Unknown', 
        'region': 'Unknown', 
        'city': 'Unknown', 
        'org': 'Unknown',
        'lat': None,
        'lng': None
    }
    IP_GEOLOCATION_CACHE[ip] = default
    return default

def check_character_substitution(domain):
    """Check for character substitution tricks (like using '0' instead of 'o')"""
    substitutions = [
        (r'0', 'o'),  # zero for o
        (r'1', 'l'),  # one for l
        (r'5', 's'),  # five for s
        (r'vv', 'w'),  # double v for w
        (r'rn', 'm'),  # rn for m
        (r'cl', 'd')   # cl for d
    ]
    
    score = 0
    for pattern, replacement in substitutions:
        if re.search(pattern, domain):
            modified = re.sub(pattern, replacement, domain)
            if modified in TRUSTED_TLDS or modified in DOMAIN_TRUST_CACHE:
                score += 0.3  # Significant increase if substitution creates a trusted domain
    
    return score

def analyze_suspicious_path(url_parts):
    """Analyze URL path and query for suspicious patterns"""
    path = url_parts.path.lower()
    query = url_parts.query.lower()
    
    suspicious_score = 0
    suspicious_patterns = []
    
    # Suspicious words in path
    suspicious_path_words = [
        'login', 'signin', 'account', 'verify', 'secure', 'password', 'auth', 'session', 
        'confirm', 'update', 'security', 'recover', 'wallet', 'payment', 'transfer',
        'validation', 'identity', 'authenticate', 'credentials', 'token'
    ]
    
    for word in suspicious_path_words:
        if word in path:
            suspicious_score += 0.15
            suspicious_patterns.append(f"Suspicious word in path: '{word}'")
    
    # Check for excessive subdomains
    subdomain_count = len(url_parts.netloc.split('.')) - 2
    if subdomain_count > 3:
        suspicious_score += subdomain_count * 0.1
        suspicious_patterns.append(f"Excessive subdomains: {subdomain_count}")
    
    # Check for long path segments (potential obfuscation)
    path_segments = [s for s in path.split('/') if s]
    for segment in path_segments:
        if len(segment) > 30:
            suspicious_score += 0.2
            suspicious_patterns.append(f"Unusually long path segment: {len(segment)} chars")
    
    # Check for data URI schemes
    if 'data:' in path or 'javascript:' in path:
        suspicious_score += 0.7
        suspicious_patterns.append("Data or JavaScript URI scheme in path")
    
    # Check for suspicious query parameters
    query_params = parse_qs(query)
    suspicious_query_params = ['token', 'auth', 'password', 'pwd', 'key', 'secret', 'credential', 'hash']
    
    for param in suspicious_query_params:
        if param in query_params:
            suspicious_score += 0.15
            suspicious_patterns.append(f"Suspicious query parameter: '{param}'")
    
    # Check for long strings in query (possible encoded content)
    for param, values in query_params.items():
        for value in values:
            if len(value) > 50:
                entropy = calculate_entropy(value)
                if entropy > 3.5:  # High entropy suggests encrypted/encoded data
                    suspicious_score += 0.25
                    suspicious_patterns.append(f"High entropy query value: {entropy:.2f}")
    
    # Check for IP address in URL
    ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url_parts.netloc):
        suspicious_score += 0.5
        suspicious_patterns.append("IP address in URL")
    
    # Check for hex or encoded characters
    hex_pattern = r'%[0-9a-fA-F]{2}'
    hex_matches = re.findall(hex_pattern, path + query)
    if len(hex_matches) > 5:
        suspicious_score += 0.2
        suspicious_patterns.append(f"Excessive hex encoding: {len(hex_matches)} instances")
    
    # Check for obfuscation techniques
    if len(path) > 0 and calculate_entropy(path) > 4:
        suspicious_score += 0.2
        suspicious_patterns.append("High entropy path (possible obfuscation)")
    
    return suspicious_score, suspicious_patterns

def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Full feature dictionary with all features (for display)
    features_dict = {
        "Domain Length": len(domain),
        "Hyphen Count (URL)": url.count('-'),
        "Dot Count (Capped at 5)": min(url.count('.'), 5),
        "Special Character Count": sum(1 for c in url if not c.isalnum()),
        "HTTPS Presence": int(url.startswith("https")),  # This will now decrease risk
        "Query Length": len(query),
        "Hyphen Count (Domain)": domain.count('-'),
        "Digit Ratio in Domain": round(sum(1 for c in domain if c.isdigit()) / (len(domain) if len(domain) > 0 else 1), 2),
        "Path Depth": len(path.split('/')) - 1,
        "Uppercase Letters in Domain": sum(c.isupper() for c in domain),
        "Domain Entropy": calculate_entropy(domain),
        "Underscore in Domain": int('_' in domain),
        "TLD Risk Score": tld_risk_score(domain.split('.')[-1] if '.' in domain and len(domain.split('.')) > 1 else ''),
        "URL Length": len(url),
        "At Symbol Present": int('@' in url),
        "JavaScript Protocol": int('javascript:' in url.lower()),
        "Data URI Scheme": int('data:' in url.lower()),
        "Parameter Count": query.count('='),
        "Long Number Sequence": int(bool(re.search(r'\d{4,}', domain))),
        "Long String Sequence": int(bool(re.search(r'[a-zA-Z]{15,}', domain))),
        # Additional features for display only (not used in model prediction)
        "Port Number Present": int(':' in domain),
        "IP Address Format": int(bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))),
        "Suspicious TLD": int(domain.split('.')[-1].lower() in ['xyz', 'top', 'loan', 'bid', 'online', 'site', 'club', 'stream', 'icu', 'live', 'vip', 'fit', 'tk', 'ml', 'ga', 'cf']),
        "Brand Name in Path": int(any(brand in path.lower() for brand in ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 'facebook', 'instagram', 'bank', 'chase', 'wellsfargo', 'citibank', 'americanexpress'])),
        "URL Encoded Characters": len(re.findall(r'%[0-9A-Fa-f]{2}', url)),
        "Suspicious File Extension": int(any(path.lower().endswith(ext) for ext in ['.exe', '.zip', '.bat', '.js', '.php', '.asp', '.cgi'])),
        "Subdomain Count": len(domain.split('.')) - 2,
        "Path Entropy": calculate_entropy(path),
        "Query Entropy": calculate_entropy(query)
    }

    # Only return the original 20 features that the model was trained on
    model_features = [
        len(domain),  # Domain Length
        url.count('-'),  # Hyphen Count (URL)
        min(url.count('.'), 5),  # Dot Count (Capped at 5)
        sum(1 for c in url if not c.isalnum()),  # Special Character Count
        int(url.startswith("https")),  # HTTPS Presence
        len(query),  # Query Length
        domain.count('-'),  # Hyphen Count (Domain)
        round(sum(1 for c in domain if c.isdigit()) / (len(domain) if len(domain) > 0 else 1), 2),  # Digit Ratio in Domain
        len(path.split('/')) - 1,  # Path Depth
        sum(c.isupper() for c in domain),  # Uppercase Letters in Domain
        calculate_entropy(domain),  # Domain Entropy
        int('_' in domain),  # Underscore in Domain
        tld_risk_score(domain.split('.')[-1] if '.' in domain and len(domain.split('.')) > 1 else ''),  # TLD Risk Score
        len(url),  # URL Length
        int('@' in url),  # At Symbol Present
        int('javascript:' in url.lower()),  # JavaScript Protocol
        int('data:' in url.lower()),  # Data URI Scheme
        query.count('='),  # Parameter Count
        int(bool(re.search(r'\d{4,}', domain))),  # Long Number Sequence
        int(bool(re.search(r'[a-zA-Z]{15,}', domain)))  # Long String Sequence
    ]

    return model_features, features_dict

def analyze_url_for_additional_patterns(url):
    """Performs a deeper analysis of URL patterns for additional risk factors"""
    suspicious_patterns = []
    risk_score = 0
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    
    # Character substitution check
    char_sub_score = check_character_substitution(domain)
    if char_sub_score > 0:
        risk_score += char_sub_score
        suspicious_patterns.append("Character substitution detected (e.g., '0' for 'o')")
    
    # Check for excessive use of subdomains
    subdomain_parts = domain.split('.')
    if len(subdomain_parts) > 3:
        risk_score += 0.2
        suspicious_patterns.append(f"Excessive subdomains: {len(subdomain_parts)}")
    
    # Check for randomness in subdomain (common in phishing)
    if len(subdomain_parts) > 2:
        subdomain = subdomain_parts[0]
        if len(subdomain) > 8 and calculate_entropy(subdomain) > 3.5:
            risk_score += 0.3
            suspicious_patterns.append("High entropy subdomain (possibly randomly generated)")
    
    # Check for brand impersonation in path
    brand_terms = ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 'facebook', 
                  'instagram', 'bank', 'chase', 'wellsfargo', 'citibank', 'americanexpress']
    
    for brand in brand_terms:
        if brand in path and brand not in domain:
            risk_score += 0.4
            suspicious_patterns.append(f"Brand name '{brand}' in path but not in domain")
    
    # Check for suspicious file extensions
    suspicious_extensions = ['.exe', '.zip', '.bat', '.js', '.php', '.asp', '.cgi']
    for ext in suspicious_extensions:
        if path.endswith(ext):
            risk_score += 0.3
            suspicious_patterns.append(f"Suspicious file extension: {ext}")
    
    # Check for obfuscation techniques
    if re.search(r'\.(php|html|asp)\?', url):
        risk_score += 0.2
        suspicious_patterns.append("Script with query parameters (potential redirect)")
    
    # Check for URL encoded characters (excessive use might indicate obfuscation)
    encoded_chars = re.findall(r'%[0-9A-Fa-f]{2}', url)
    if len(encoded_chars) > 3:
        risk_score += 0.2
        suspicious_patterns.append(f"Excessive URL encoding: {len(encoded_chars)} instances")
    
    # Check for numeric IP address instead of domain
    ip_pattern = r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, url):
        risk_score += 0.5
        suspicious_patterns.append("IP address used instead of domain name")
    
    # Check for suspicious URL shorteners
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            risk_score += 0.3
            suspicious_patterns.append(f"URL shortener detected: {shortener}")
    
    # Path/query specific analysis
    path_score, path_patterns = analyze_suspicious_path(parsed_url)
    risk_score += path_score
    suspicious_patterns.extend(path_patterns)
    
    return risk_score, suspicious_patterns

def is_domain_popular(domain):
    """Use algorithmic approaches to determine if a domain is likely to be popular/legitimate"""
    extracted = tldextract.extract(domain)
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    
    # Check cache first
    if domain_name in DOMAIN_TRUST_CACHE:
        return DOMAIN_TRUST_CACHE[domain_name], get_domain_category(domain_name)
    
    # Domain popularity signals
    popularity_score = 0
    max_score = 9
    
    # 1. Domain length (shorter domains tend to be more legitimate/popular)
    # Domains between 3-12 chars get higher scores
    domain_length = len(extracted.domain)
    if 3 <= domain_length <= 12:
        popularity_score += 1
    elif 13 <= domain_length <= 20:
        popularity_score += 0.5
    
    # 2. Domain entropy (legitimate domains tend to have lower entropy - more readable)
    entropy = calculate_entropy(extracted.domain)
    if entropy < 2.8:
        popularity_score += 1
    elif entropy < 3.2:
        popularity_score += 0.5
    
    # 3. TLD popularity/legitimacy
    if extracted.suffix in TRUSTED_TLDS or extracted.suffix == "com":
        popularity_score += 2
    elif extracted.suffix in ['org', 'net', 'io', 'co']:
        popularity_score += 1
    
    # 4. No digits (popular domains rarely contain digits)
    if not any(c.isdigit() for c in extracted.domain):
        popularity_score += 1
    
    # 5. No hyphens (popular domains rarely use hyphens)
    if '-' not in extracted.domain:
        popularity_score += 1
    
    # 6. No special characters (popular domains don't use special chars)
    if all(c.isalnum() or c == '-' for c in extracted.domain):
        popularity_score += 1
    
    # 7. All lowercase (legitimate domains are typically all lowercase)
    if extracted.domain.islower():
        popularity_score += 1
    
    # 8. Dictionary words (domains that contain dictionary words are often legitimate)
    words = re.findall(r'[a-z]{3,}', extracted.domain.lower())
    if words and len(words[0]) >= 3:
        popularity_score += 1
    
    # Decide if domain is popular based on score threshold
    is_popular = popularity_score >= max_score * 0.6
    
    # Get domain category
    category = get_domain_category(domain_name)
    
    # Cache the result
    DOMAIN_TRUST_CACHE[domain_name] = is_popular
    
    return is_popular, category

def get_domain_info(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Try to get the IP address
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = None
        
        # Get more info using ipinfo.io
        org = None
        country = None
        city = None
        region = None
        latitude = None
        longitude = None
        has_coordinates = False
        
        if ip_address:
            try:
                response = requests.get(f"https://ipinfo.io/{ip_address}/json")
                if response.status_code == 200:
                    data = response.json()
                    org = data.get('org')
                    country = data.get('country')
                    city = data.get('city')
                    region = data.get('region')
                    
                    # Extract coordinates if available
                    if 'loc' in data and data['loc']:
                        try:
                            lat_long = data['loc'].split(',')
                            if len(lat_long) == 2:
                                latitude = float(lat_long[0])
                                longitude = float(lat_long[1])
                                has_coordinates = True
                        except:
                            pass
            except:
                pass
        
        return {
            "ip_address": ip_address,
            "organization": org,
            "country": country,
            "city": city,
            "region": region,
            "latitude": latitude,
            "longitude": longitude,
            "has_coordinates": has_coordinates
        }
    except:
        return None

def get_domain_category(domain):
    """Determine the likely category of a domain"""
    if domain in DOMAIN_CATEGORY_CACHE:
        return DOMAIN_CATEGORY_CACHE[domain]
    
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower()
    
    # Count matches for each category
    category_scores = {}
    for category, keywords in DOMAIN_CATEGORIES.items():
        # Count how many keywords from this category appear in the domain
        matches = sum(1 for keyword in keywords if keyword in domain_name)
        if matches > 0:
            category_scores[category] = matches
    
    # Find the category with the highest score
    if category_scores:
        top_category = max(category_scores.items(), key=lambda x: x[1])[0]
        DOMAIN_CATEGORY_CACHE[domain] = top_category
        return top_category
    
    # Default category if no strong match
    DOMAIN_CATEGORY_CACHE[domain] = "general"
    return "general"

def is_url_shortener(domain):
    """Check if the domain is a known URL shortener"""
    return any(domain.lower().endswith(shortener) for shortener in URL_SHORTENERS)

def is_trusted_domain(url):
    """Algorithm-based approach to determine if a domain is trusted"""
    extracted = tldextract.extract(url)
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    
    # Check cache first
    if domain_name in DOMAIN_TRUST_CACHE:
        return DOMAIN_TRUST_CACHE[domain_name]
    
    # Inherently risky patterns
    if is_url_shortener(domain_name):
        DOMAIN_TRUST_CACHE[domain_name] = False
        return False
    
    # High risk patterns
    suspicious_patterns = [
        r'[a-zA-Z0-9]{10,}\.', # Random-looking prefix
        r'\d{5,}',  # Long number sequences
        r'(login|signin|security|verify|account|password|credential).*(\.(?!com|org|net|edu|gov)\w+)', # Login + suspicious TLD
        r'(payment|bank|wallet|crypto|bitcoin).*(\.(?!com|org|net|edu|gov)\w+)' # Financial + suspicious TLD
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain_name, re.IGNORECASE):
            DOMAIN_TRUST_CACHE[domain_name] = False
            return False
    
    # Check for trusted TLDs
    if extracted.suffix.split('.')[-1].lower() in TRUSTED_TLDS:
        DOMAIN_TRUST_CACHE[domain_name] = True
        return True
        
    # Use algorithmic approach to assess domain popularity/legitimacy
    is_popular, _ = is_domain_popular(domain_name)
    
    # Cache result
    DOMAIN_TRUST_CACHE[domain_name] = is_popular
    return is_popular

def calibrate_prediction(prediction, url, url_pattern_score):
    """Apply calibration with more weight on URL pattern analysis and security features"""
    extracted = tldextract.extract(url)
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    
    # Base calibration - less extreme prediction
    calibrated = (prediction * 0.75) + 0.05
    
    # HTTPS presence should significantly decrease risk - apply this early
    if url.startswith('https'):
        calibrated = calibrated * 0.5  # Reduce risk by 50% for HTTPS (previously 30%)
    
    # Check if domain is algorithmically determined to be popular/legitimate
    is_popular, category = is_domain_popular(domain_name)
    
    # URL pattern analysis now has a stronger weight in the calibration
    calibrated = (calibrated * 0.6) + (url_pattern_score * 0.4)
    
    # Apply domain-based calibration with less weight
    if is_trusted_domain(url):
        # Trusted domains get a smaller reduction
        trusted_calibration = calibrated * 0.4
        # Ensure this doesn't override high URL pattern scores
        calibrated = max(trusted_calibration, url_pattern_score * 0.5)
    
    # Domain length calibration - with less influence
    if len(extracted.domain) <= 6 and not re.search(r'\d', extracted.domain):
        calibrated = calibrated * 0.85
    
    # Domain entropy calibration - also with less influence
    domain_entropy = calculate_entropy(extracted.domain)
    if domain_entropy > 3.5:  # High entropy suggests randomness (suspicious)
        calibrated = min(calibrated * 1.2, 0.99)
    elif domain_entropy < 2.8:  # Low entropy suggests readable names (legitimate)
        calibrated = max(calibrated * 0.9, 0.01)
    
    # TLD calibration - less impact
    if extracted.suffix in ['com', 'org', 'net', 'edu', 'gov']:
        calibrated = calibrated * 0.9
    
    # Additional security feature calibrations
    if ':' in extracted.domain:  # Port number present
        calibrated = min(calibrated * 1.3, 0.99)
    
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', extracted.domain):  # IP address format
        calibrated = min(calibrated * 1.4, 0.99)
    
    if extracted.suffix.lower() in ['xyz', 'top', 'loan', 'bid', 'online', 'site', 'club', 'stream', 'icu', 'live', 'vip', 'fit', 'tk', 'ml', 'ga', 'cf']:
        calibrated = min(calibrated * 1.2, 0.99)
    
    # Final adjustment for HTTPS URLs with risky patterns
    if url.startswith('https') and url_pattern_score > 0.7:
        # Even for HTTPS, high risk patterns shouldn't be ignored
        calibrated = max(calibrated, url_pattern_score * 0.3)
    elif not url.startswith('https'):
        # Non-HTTPS URLs get a minimum risk level
        calibrated = max(calibrated, 0.2)  # At least 20% risk for non-HTTPS
    
    # Cap the maximum risk at 99%
    return min(calibrated, 0.99)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('weblogin.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('weblogin.html', register=True)
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('weblogin.html', register=True)
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('weblogin.html', register=True)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/predict", methods=["POST"])
def predict():
    if request.method == 'POST':
        url = request.form.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL provided"})
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Extract base URL for display
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.netloc}{parsed_url.path}"
        if not base_url.strip():
            base_url = url
            
        try:
            # Extract features
            features_list, features_dict = extract_features(url)
            
            # Get text features for the model
            tokens = tokenizer.texts_to_sequences([url])
            text_features = pad_sequences(tokens, maxlen=MAX_LEN)
            
            # Scale numerical features using the saved scaler
            scaled_features = scaler.transform([features_list])
            
            # Get prediction using the main model
            prediction = model.predict([text_features, scaled_features])[0][0]
            
            # Analyze for suspicious URL patterns
            url_pattern_score, suspicious_patterns = analyze_url_for_additional_patterns(url)
            
            # Get domain information
            domain_info = get_domain_info(url)
            
            # Check if this is a trusted domain
            extracted = tldextract.extract(url)
            domain_name = f"{extracted.domain}.{extracted.suffix}"
            is_trusted = is_trusted_domain(url)
            is_popular, domain_category = is_domain_popular(domain_name)
            
            # NEW BALANCED RISK CALCULATION
            # Start with base risk components
            base_features_weight = 0.6  # 60% from regular URL features
            pattern_weight = 0.3       # 30% from suspicious patterns (increased weight)
            domain_info_weight = 0.1   # 10% from domain information
            
            # Calculate base feature risk (initial model prediction, with mild calibration)
            # But don't apply the strong HTTPS reduction from calibrate_prediction() here
            base_feature_risk = prediction * 0.8  # Just mild calibration
            
            # Calculate pattern risk (with increased weight)
            pattern_risk = 0
            if suspicious_patterns:
                # Increase impact per pattern
                pattern_risk = min(1.0, len(suspicious_patterns) * 0.15)
            
            # Calculate domain info risk
            domain_info_risk = 0
            missing_info_count = 0
            if domain_info:
                # Check each piece of domain info
                if domain_info.get('ip_address') is None:
                    missing_info_count += 1
                if domain_info.get('organization') is None or domain_info.get('organization') == 'Unknown':
                    missing_info_count += 1
                if domain_info.get('country') is None or domain_info.get('country') == 'Unknown':
                    missing_info_count += 1
                if (domain_info.get('city') is None or domain_info.get('city') == 'Unknown') and \
                   (domain_info.get('region') is None or domain_info.get('region') == 'Unknown'):
                    missing_info_count += 1
                
                # Calculate risk based on missing info
                domain_info_risk = missing_info_count / 4  # Normalized to 0-1
            else:
                # If entire domain_info is missing
                domain_info_risk = 1.0
            
            # Calculate weighted components
            weighted_feature_risk = base_feature_risk * base_features_weight
            weighted_pattern_risk = pattern_risk * pattern_weight
            weighted_domain_risk = domain_info_risk * domain_info_weight
            
            # Calculate raw risk score (sum of weighted components)
            raw_risk = weighted_feature_risk + weighted_pattern_risk + weighted_domain_risk
            
            # Apply final adjustments - more balanced approach
            if is_trusted:
                # Reduce risk for trusted domains, but less aggressively
                raw_risk = raw_risk * 0.85
            
            # More balanced HTTPS adjustment - reduce impact significantly
            if url.startswith('https'):
                # HTTPS reduces risk by 20% now instead of 80%
                raw_risk = raw_risk * 0.8
            
            # Cap between 5% and 95% to avoid extremes
            final_risk = max(min(raw_risk, 0.95), 0.05)
            
            # Scale to percentage for display
            fraud_score = int(final_risk * 100)
            
            # Create normalized feature contributions that add up to exactly the fraud_score
            feature_contributions = []
            
            # Create a dictionary with only the 20 features used by the model
            model_features_dict = {
                "Domain Length": features_list[0],
                "Hyphen Count (URL)": features_list[1],
                "Dot Count (Capped at 5)": features_list[2],
                "Special Character Count": features_list[3],
                "HTTPS Presence": features_list[4],
                "Query Length": features_list[5],
                "Hyphen Count (Domain)": features_list[6],
                "Digit Ratio in Domain": features_list[7],
                "Path Depth": features_list[8],
                "Uppercase Letters in Domain": features_list[9],
                "Domain Entropy": features_list[10],
                "Underscore in Domain": features_list[11],
                "TLD Risk Score": features_list[12],
                "URL Length": features_list[13],
                "At Symbol Present": features_list[14],
                "JavaScript Protocol": features_list[15],
                "Data URI Scheme": features_list[16],
                "Parameter Count": features_list[17],
                "Long Number Sequence": features_list[18],
                "Long String Sequence": features_list[19]
            }
            
            # Calculate raw contribution scores for each feature
            raw_contributions = []
            for idx, (name, value) in enumerate(model_features_dict.items()):
                # Handle HTTPS with less influence (reduced from 60% to 30%)
                if name == "HTTPS Presence" and value == 1:
                    direction = "decreases"
                    raw_score = 30  # Reduced HTTPS influence
                else:
                    direction = "increases" if scaled_features[0][idx] > 0.5 else "decreases"
                    raw_score = min(int(abs(scaled_features[0][idx] * 20)), 100)
                
                raw_contributions.append({
                    "name": name,
                    "value": value,
                    "raw_score": raw_score,
                    "direction": direction
                })
            
            # Add domain info factors
            if missing_info_count > 0:
                missing_factors = []
                if not domain_info or domain_info.get('ip_address') is None:
                    missing_factors.append("Unknown IP address")
                if not domain_info or domain_info.get('organization') is None or domain_info.get('organization') == 'Unknown':
                    missing_factors.append("Unknown organization")
                if not domain_info or domain_info.get('country') is None or domain_info.get('country') == 'Unknown':
                    missing_factors.append("Unknown country")
                if not domain_info or ((domain_info.get('city') is None or domain_info.get('city') == 'Unknown') and 
                   (domain_info.get('region') is None or domain_info.get('region') == 'Unknown')):
                    missing_factors.append("Unknown location")
                
                for factor in missing_factors:
                    raw_contributions.append({
                        "name": factor,
                        "value": "Unknown",
                        "raw_score": 25,  # Base score for missing info
                        "direction": "increases"
                    })
            
            # Add suspicious pattern factors with higher weight
            if suspicious_patterns:
                raw_contributions.append({
                    "name": f"Suspicious patterns ({len(suspicious_patterns)} detected)",
                    "value": len(suspicious_patterns),
                    "raw_score": min(70, len(suspicious_patterns) * 15),  # Higher weight for patterns
                    "direction": "increases"
                })
            
            # Now normalize all contributions to add up to exactly the fraud_score
            # First, sum all raw contribution scores
            total_raw_score = sum(c["raw_score"] for c in raw_contributions)
            
            # Then calculate the normalized percentage for each
            for contribution in raw_contributions:
                normalized_percentage = int((contribution["raw_score"] / total_raw_score) * fraud_score) if total_raw_score > 0 else 0
            
            feature_contributions.append({
                    "name": contribution["name"],
                    "value": contribution["value"],
                    "percentage": normalized_percentage,
                    "direction": contribution["direction"]
                })
            
            # Ensure the sum of percentages equals the fraud_score exactly
            # Adjust the first item if needed
            sum_percentages = sum(c["percentage"] for c in feature_contributions)
            if sum_percentages != fraud_score and feature_contributions:
                feature_contributions[0]["percentage"] += (fraud_score - sum_percentages)
            
            # Sort by contribution percentage (highest first)
            feature_contributions.sort(key=lambda x: x["percentage"], reverse=True)

            response = {
                "url": url,
                "base_url": base_url,
                "fraud_score": fraud_score,
                "domain_info": domain_info,
                "suspicious_patterns": suspicious_patterns,
                "is_trusted_domain": is_trusted,
                "is_special_domain": domain_name in TRUSTED_DOMAINS,
                "domain_category": domain_category,
                "domain_info_display": TRUSTED_DOMAINS.get(domain_name, {}).get("display", None),
                "feature_contributions": feature_contributions
            }

            return jsonify(response)
            
        except Exception as e:
            app.logger.error(f"Error processing URL: {str(e)}")
            return jsonify({"error": f"Error processing URL: {str(e)}"})
    
    return jsonify({"error": "Invalid request method"})

if __name__ == "__main__":
    app.run(debug=True)