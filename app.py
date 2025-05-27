from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from uuid import uuid4
import re
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

# Google Safe Browsing API key
api_key = os.getenv("GOOGLE_API_KEY")
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

# Attack type descriptions
ATTACK_DESCRIPTIONS = {
    "Malware": {
        "description": "Malware, short for malicious software, refers to a wide range of harmful programs designed to infiltrate and damage computers, networks, or devices without user consent. These include viruses that corrupt files, worms that spread across networks, ransomware that locks critical data for ransom, and spyware that silently collects sensitive information like passwords or financial details. Malware often spreads through deceptive tactics, such as fake software updates, malicious email attachments, or compromised websites, posing severe risks to user privacy, data integrity, and system functionality. Attackers exploit vulnerabilities in outdated software or rely on user error to gain unauthorized access, making malware a persistent and evolving threat in the digital landscape. Its impact can range from minor performance issues to catastrophic data breaches, affecting individuals, businesses, and critical infrastructure alike.",
        "prevention": [
            "Install and regularly update reputable antivirus software to detect and neutralize malware threats.",
            "Avoid downloading files or software from unverified websites or peer-to-peer networks.",
            "Enable a robust firewall to block unauthorized network connections.",
            "Keep your operating system and applications updated to patch known security vulnerabilities.",
            "Exercise caution with email attachments and links, verifying the sender’s identity before interaction.",
            "Use ad-blockers to minimize exposure to malicious advertisements that may deliver malware.",
            "Regularly back up critical data to an external or cloud-based storage solution."
        ]
    },
    "Social Engineering": {
        "description": "Social engineering attacks exploit human psychology to manipulate individuals into divulging sensitive information or performing actions that compromise security. Unlike traditional hacking, these attacks rely on deception rather than technical exploits, using tactics like phishing emails, pretexting, baiting, or impersonation. For example, attackers may pose as trusted entities—such as banks, tech support, or colleagues—to trick users into revealing login credentials, financial details, or clicking malicious links. Phishing, the most common form, often uses urgent or fear-inducing language to prompt hasty actions. These attacks are highly effective because they target human trust, bypassing even robust technical defenses. Social engineering can lead to identity theft, financial loss, or unauthorized access to corporate systems, making it a critical threat in both personal and professional contexts.",
        "prevention": [
            "Verify the authenticity of unsolicited emails, calls, or messages before responding or clicking links.",
            "Enable two-factor authentication (2FA) on all accounts to add an extra layer of security.",
            "Educate yourself and others on recognizing phishing signs, such as urgent language or misspelled domains.",
            "Use a password manager to create and store strong, unique passwords for each account.",
            "Check website URLs for subtle misspellings or unusual domain extensions before entering credentials.",
            "Report suspicious communications to your IT department or email provider immediately.",
            "Avoid sharing personal or sensitive information over unverified channels."
        ]
    },
    "Unwanted Software": {
        "description": "Unwanted software, sometimes called potentially unwanted programs (PUPs), includes applications that perform undesirable actions without clear user consent. These programs may display intrusive ads, track browsing habits, redirect searches, or modify browser settings, often degrading system performance and compromising privacy. Commonly bundled with free software downloads, unwanted software is installed when users overlook fine print or opt for default installation settings. While not always malicious, it can serve as a gateway for more severe threats, such as malware or data theft, by exploiting system vulnerabilities or user trust. Its covert nature makes it challenging to detect, as users may attribute slowdowns or pop-ups to other issues, allowing the software to persist and potentially escalate risks over time.",
        "prevention": [
            "Download software exclusively from trusted sources, such as official websites or verified app stores.",
            "Always choose custom installation options to deselect bundled unwanted software.",
            "Read user reviews and research applications before downloading to identify potential risks.",
            "Use anti-malware tools to regularly scan and remove unwanted programs from your device.",
            "Monitor your browser for unauthorized extensions, toolbars, or altered settings.",
            "Uninstall unfamiliar or suspicious applications promptly through your system’s control panel.",
            "Keep your browser and security software updated to block known unwanted software threats."
        ]
    },
    "Potentially Harmful Application": {
        "description": "Potentially harmful applications (PHAs) are programs that may not be explicitly malicious but pose significant risks to user security and privacy. These include apps with excessive permissions, rogue VPNs, fake antivirus tools, or software that bypasses security protocols to access sensitive data or system resources. Often distributed through unofficial app stores, PHAs may disguise themselves as legitimate utilities, tricking users into installation. Once active, they can steal personal information, display deceptive alerts, or enable backdoors for further attacks. Their subtle nature makes them dangerous, as users may not immediately recognize the threat, allowing PHAs to operate undetected. In mobile and desktop environments, PHAs can compromise device performance, expose sensitive data, or facilitate broader cyber attacks.",
        "prevention": [
            "Install applications only from reputable platforms, such as Google Play, Apple App Store, or official websites.",
            "Review and restrict app permissions to prevent access to unnecessary data or functions.",
            "Keep your operating system and apps updated to close security gaps exploited by PHAs.",
            "Use mobile or desktop security software to scan for and remove potentially harmful applications.",
            "Avoid sideloading apps from unverified sources or third-party websites.",
            "Regularly audit installed apps for suspicious behavior, such as high resource usage or unauthorized access.",
            "Enable app verification settings on your device to block unauthorized installations."
        ]
    }
}

def analyze_url_features(url):
    """Extract features for ML-like confidence scoring."""
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    features = {
        "url_length": len(url),
        "special_chars": len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url)),
        "subdomains": len(domain.split('.')) - 2,  # e.g., sub.example.com -> 1
        "https": 1 if parsed.scheme == "https" else 0,
        "suspicious_keywords": sum(1 for kw in ['login', 'secure', 'account', 'verify'] if kw in url.lower())
    }
    # Simple heuristic scoring (mimics ML model output)
    score = 100
    if features["url_length"] > 100:
        score -= 20
    if features["special_chars"] > 5:
        score -= 15
    if features["subdomains"] > 2:
        score -= 10
    if not features["https"]:
        score -= 15
    if features["suspicious_keywords"] > 1:
        score -= 20
    return max(10, min(90, score))

def check_website_safety(url):
    payload = {
        "client": {
            "clientId": "browsafe-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()

        # Calculate confidence score
        feature_score = analyze_url_features(url)
        if "matches" in result:
            reasons = [match["threatType"].replace("_", " ").title() for match in result["matches"]]
            threat_severity = {
                "Malware": 0.3,
                "Social Engineering": 0.25,
                "Unwanted Software": 0.2,
                "Potentially Harmful Application": 0.15
            }
            api_score = 100 - (sum(threat_severity.get(threat, 0.1) for threat in reasons) * 100 / len(reasons))
            # Combine API and feature-based scores (weighted average)
            confidence = (0.7 * api_score + 0.3 * feature_score)
            confidence = max(10, min(90, confidence))  # Clamp between 10% and 90%
            detailed_reasons = [
                {"type": reason, **ATTACK_DESCRIPTIONS.get(reason, {"description": "Unknown threat", "prevention": []})}
                for reason in reasons
            ]
            return {
                "safe": False,
                "reasons": detailed_reasons,
                "confidence": round(confidence, 2),
                "check_id": str(uuid4())
            }
        else:
            confidence = (0.7 * 95 + 0.3 * feature_score)  # High base score for safe sites
            return {
                "safe": True,
                "reasons": [],
                "confidence": round(confidence, 2),
                "check_id": str(uuid4())
            }
    except requests.RequestException as e:
        feature_score = analyze_url_features(url)
        return {
            "safe": False,
            "reasons": [{"type": "Error", "description": str(e), "prevention": []}],
            "confidence": round(feature_score * 0.5, 2),  # Lower confidence on error
            "check_id": str(uuid4())
        }

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = check_website_safety(url)
    return jsonify(result)

# Serve index.html at the root URL
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

# Serve other static files (CSS, JS, etc.)
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))  # Use PORT env var, default to 5000 locally
    app.run(host="0.0.0.0", port=port, debug=True)