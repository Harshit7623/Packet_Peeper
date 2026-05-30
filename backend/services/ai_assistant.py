"""
AI-Powered Security Assistant for Packet Peeper
Provides intelligent threat remediation and explanations for non-technical users
"""

import os
import json
import time
import logging
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

from config.config import AI_CACHE_TTL, AI_CACHE_MAX, AI_DEBUG

logger = logging.getLogger('packet_peeper.ai')


class AIProvider(Enum):
    """Supported AI providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    FALLBACK = "fallback"  # Built-in responses when no API available


@dataclass
class AIResponse:
    """Structured AI response"""
    success: bool
    explanation: str
    steps: List[str]
    severity_assessment: str
    estimated_risk: str
    technical_details: Optional[str] = None
    prevention_tips: List[str] = None
    provider: str = "fallback"
    cached: bool = False
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.prevention_tips is None:
            self.prevention_tips = []
    
    def to_dict(self) -> Dict:
        return asdict(self)


class AISecurityAssistant:
    """
    AI-powered security assistant that provides:
    - Plain-language explanations of threats
    - Step-by-step remediation guidance
    - Risk assessment for non-technical users
    """
    
    def __init__(self, provider: str = None, api_key: str = None):
        self.provider = self._detect_provider(provider, api_key)
        self.api_key = api_key or os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("AI_MODEL", "gpt-4o-mini")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.cache = {}  # Simple in-memory cache
        self.cache_ttl = AI_CACHE_TTL
        self.cache_max = AI_CACHE_MAX
        
        logger.info(f"[AI] Assistant initialized with provider: {self.provider.value}")
    
    def _detect_provider(self, provider: str, api_key: str) -> AIProvider:
        """Auto-detect the best available AI provider"""
        if provider:
            return AIProvider(provider.lower())
        
        # Check for API keys
        if api_key or os.getenv("OPENAI_API_KEY"):
            return AIProvider.OPENAI
        if os.getenv("ANTHROPIC_API_KEY"):
            return AIProvider.ANTHROPIC
        
        # Check for local Ollama
        try:
            import requests
            resp = requests.get(f"{os.getenv('OLLAMA_URL', 'http://localhost:11434')}/api/tags", timeout=2)
            if resp.status_code == 200:
                return AIProvider.OLLAMA
        except:
            pass
        
        return AIProvider.FALLBACK
    
    def _get_cache_key(self, alert_type: str, context: Dict) -> str:
        """Generate cache key for response caching"""
        content = f"{alert_type}:{json.dumps(context, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[AIResponse]:
        """Check if response is cached and still valid"""
        self._prune_cache()
        if cache_key in self.cache:
            cached_time, response = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                response.cached = True
                return response
        return None
    
    def _save_cache(self, cache_key: str, response: AIResponse):
        """Save response to cache"""
        self.cache[cache_key] = (time.time(), response)
        self._prune_cache()

    def _prune_cache(self) -> None:
        """Remove expired cache entries and enforce max size."""
        if not self.cache:
            return

        now = time.time()
        expired_keys = [
            key for key, (cached_time, _) in self.cache.items()
            if now - cached_time >= self.cache_ttl
        ]
        for key in expired_keys:
            self.cache.pop(key, None)

        if len(self.cache) <= self.cache_max:
            return

        overflow = len(self.cache) - self.cache_max
        oldest = sorted(self.cache.items(), key=lambda item: item[1][0])
        for key, _ in oldest[:overflow]:
            self.cache.pop(key, None)
    
    def get_remediation(self, alert: Dict) -> AIResponse:
        """
        Get AI-powered remediation advice for a security alert
        
        Args:
            alert: Alert dictionary with type, title, description, evidence, etc.
        
        Returns:
            AIResponse with explanation, steps, and recommendations
        """
        # Get and normalize alert type - check ALL possible field names
        alert_type_raw = alert.get('type') or alert.get('alert_type') or alert.get('attack_type') or 'unknown'
        
        # If alert_type is 'security' (generic category), try to extract actual type from title
        if alert_type_raw.lower() == 'security':
            title = alert.get('title', '').lower()
            if 'ddos' in title:
                alert_type_raw = 'ddos'
            elif 'c2' in title or 'beacon' in title:
                alert_type_raw = 'c2_beacon'
            elif 'port scan' in title or 'scan' in title:
                alert_type_raw = 'port_scan'
            elif 'land attack' in title:
                alert_type_raw = 'land_attack'
            elif 'spoof' in title:
                alert_type_raw = 'ip_spoofing'
            elif 'brute' in title:
                alert_type_raw = 'brute_force'
            elif 'sql' in title:
                alert_type_raw = 'sql_injection'
            elif 'xss' in title:
                alert_type_raw = 'xss'
            elif 'dns' in title and 'tunnel' in title:
                alert_type_raw = 'dns_tunneling'
            elif 'arp' in title:
                alert_type_raw = 'arp_spoofing'
            elif 'exfil' in title:
                alert_type_raw = 'data_exfiltration'
            elif 'flood' in title:
                alert_type_raw = 'dos_flood'
        
        alert_type = alert_type_raw.lower().replace(' ', '_').replace('-', '_')
        
        if AI_DEBUG:
            logger.debug(
                "[AI] Processing alert: raw_type='%s', normalized='%s', title='%s'",
                alert_type_raw,
                alert_type,
                alert.get('title', 'N/A')
            )
        logger.info(f"[AI] Alert type normalized: '{alert_type_raw}' -> '{alert_type}'")
        
        context = {
            'title': alert.get('title', ''),
            'description': alert.get('description', ''),
            'severity': alert.get('severity', 'medium'),
            'source': alert.get('source', 'unknown'),
            'evidence': alert.get('evidence', {}),
        }
        
        # Check cache first (use alert_type only for cache to allow similar alerts to get same response)
        cache_key = f"{alert_type}_{context['severity']}"
        cached = self._check_cache(cache_key)
        if cached:
            if AI_DEBUG:
                logger.debug("[AI] Returning cached response for type='%s'", alert_type)
            return cached
        
        # Route to appropriate provider
        logger.info(f"[AI] Generating new response for type='{alert_type}' using provider={self.provider}")
        if self.provider == AIProvider.OPENAI:
            response = self._call_openai(alert_type, context)
        elif self.provider == AIProvider.ANTHROPIC:
            response = self._call_anthropic(alert_type, context)
        elif self.provider == AIProvider.OLLAMA:
            response = self._call_ollama(alert_type, context)
        else:
            response = self._get_fallback_response(alert_type, context)
        
        # Cache the response
        self._save_cache(cache_key, response)
        
        logger.info(f"[AI] Response generated for type='{alert_type}': {response.steps[:1] if response.steps else 'no steps'}")
        
        return response
    
    def _build_prompt(self, alert_type: str, context: Dict) -> str:
        """Build the prompt for the AI model"""
        return f"""You are a friendly cybersecurity assistant helping a non-technical home user understand and fix a network security issue.

SECURITY ALERT DETAILS:
- Alert Type: {alert_type}
- Title: {context['title']}
- Description: {context['description']}
- Severity: {context['severity']}
- Source IP/Device: {context['source']}
- Evidence: {json.dumps(context['evidence'], indent=2) if context['evidence'] else 'None provided'}

Please provide a response in the following JSON format:
{{
    "explanation": "A simple, non-technical explanation of what this alert means (2-3 sentences, avoid jargon)",
    "severity_assessment": "How serious this is: 'Not Urgent', 'Moderate Concern', 'Needs Attention', or 'Critical - Act Now'",
    "estimated_risk": "What could happen if ignored: brief description",
    "steps": [
        "Step 1: First action to take (be specific and simple)",
        "Step 2: Next action...",
        "Step 3: Follow-up action..."
    ],
    "prevention_tips": [
        "Tip 1: How to prevent this in the future",
        "Tip 2: Another prevention measure"
    ],
    "technical_details": "Optional: Brief technical explanation for advanced users"
}}

Remember: The user is NOT technical. Use simple language like you're explaining to a family member. Be reassuring but honest about risks."""
    
    def _call_openai(self, alert_type: str, context: Dict) -> AIResponse:
        """Call OpenAI API for remediation advice"""
        try:
            import openai
            
            client = openai.OpenAI(api_key=self.api_key)
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant. Always respond with valid JSON."},
                    {"role": "user", "content": self._build_prompt(alert_type, context)}
                ],
                temperature=0.7,
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            
            return AIResponse(
                success=True,
                explanation=result.get('explanation', 'Unable to analyze this alert.'),
                steps=result.get('steps', ['Review the alert details manually.']),
                severity_assessment=result.get('severity_assessment', 'Unknown'),
                estimated_risk=result.get('estimated_risk', 'Unknown risk level'),
                technical_details=result.get('technical_details'),
                prevention_tips=result.get('prevention_tips', []),
                provider='openai'
            )
            
        except ImportError:
            logger.warning("OpenAI package not installed, falling back to built-in responses")
            return self._get_fallback_response(alert_type, context)
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return self._get_fallback_response(alert_type, context)
    
    def _call_anthropic(self, alert_type: str, context: Dict) -> AIResponse:
        """Call Anthropic Claude API for remediation advice"""
        try:
            import anthropic
            
            client = anthropic.Anthropic(api_key=self.api_key or os.getenv("ANTHROPIC_API_KEY"))
            
            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                messages=[
                    {"role": "user", "content": self._build_prompt(alert_type, context)}
                ]
            )
            
            # Parse JSON from response
            result = json.loads(message.content[0].text)
            
            return AIResponse(
                success=True,
                explanation=result.get('explanation', 'Unable to analyze this alert.'),
                steps=result.get('steps', ['Review the alert details manually.']),
                severity_assessment=result.get('severity_assessment', 'Unknown'),
                estimated_risk=result.get('estimated_risk', 'Unknown risk level'),
                technical_details=result.get('technical_details'),
                prevention_tips=result.get('prevention_tips', []),
                provider='anthropic'
            )
            
        except ImportError:
            logger.warning("Anthropic package not installed, falling back to built-in responses")
            return self._get_fallback_response(alert_type, context)
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return self._get_fallback_response(alert_type, context)
    
    def _call_ollama(self, alert_type: str, context: Dict) -> AIResponse:
        """Call local Ollama for remediation advice"""
        try:
            import requests
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": os.getenv("OLLAMA_MODEL", "llama3.2"),
                    "prompt": self._build_prompt(alert_type, context),
                    "stream": False,
                    "format": "json"
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = json.loads(response.json()['response'])
                
                return AIResponse(
                    success=True,
                    explanation=result.get('explanation', 'Unable to analyze this alert.'),
                    steps=result.get('steps', ['Review the alert details manually.']),
                    severity_assessment=result.get('severity_assessment', 'Unknown'),
                    estimated_risk=result.get('estimated_risk', 'Unknown risk level'),
                    technical_details=result.get('technical_details'),
                    prevention_tips=result.get('prevention_tips', []),
                    provider='ollama'
                )
            else:
                raise Exception(f"Ollama returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return self._get_fallback_response(alert_type, context)
    
    def _get_fallback_response(self, alert_type: str, context: Dict) -> AIResponse:
        """
        Built-in responses when no AI API is available.
        These are carefully crafted for common attack types.
        """
        severity = context.get('severity', 'medium')
        source = context.get('source', 'unknown device')
        
        if AI_DEBUG:
            logger.debug("[AI] Looking up fallback response for: '%s'", alert_type)
        
        # Comprehensive fallback responses for each attack type
        responses = {
            'port_scan': AIResponse(
                success=True,
                explanation=f"Someone or something is checking your network to find open doors (ports). Think of it like someone walking around your house, trying each door and window to see if any are unlocked.",
                steps=[
                    "Check if you recognize the device at {source}. Is it one of your computers or phones?",
                    "If you don't recognize the device, disconnect it from your Wi-Fi immediately",
                    "Change your Wi-Fi password to kick out any unknown devices",
                    "Check your router's connected devices list for anything suspicious"
                ],
                severity_assessment="Needs Attention" if severity in ['high', 'critical'] else "Moderate Concern",
                estimated_risk="If this is an attacker, they're mapping your network to find vulnerabilities. This is often the first step before a real attack.",
                prevention_tips=[
                    "Use a strong, unique Wi-Fi password",
                    "Enable your router's built-in firewall",
                    "Regularly check for unknown devices on your network"
                ],
                technical_details=f"Port scanning detected from {source}. Common reconnaissance technique.",
                provider='fallback'
            ),
            
            'dos_flood': AIResponse(
                success=True,
                explanation=f"Your network is being flooded with fake traffic from {source}. It's like someone calling your phone thousands of times per second to keep it busy so real calls can't get through.",
                steps=[
                    "Restart your router by unplugging it for 30 seconds, then plugging it back in",
                    "If the attack continues, contact your internet provider (ISP)",
                    "Check if the source IP ({source}) is from your own network - it might be a compromised device",
                    "Consider enabling DoS protection in your router settings if available"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Your internet connection may slow down or stop working. Other devices on your network may also be affected.",
                prevention_tips=[
                    "Keep your router firmware updated",
                    "Enable SYN flood protection if your router supports it",
                    "Consider a router with built-in DDoS protection"
                ],
                technical_details="SYN flood attack detected. High volume of half-open connections exhausting resources.",
                provider='fallback'
            ),
            
            'brute_force': AIResponse(
                success=True,
                explanation=f"Someone is trying to guess the password to one of your devices or services. They're trying many different passwords very quickly, like a burglar trying thousands of keys on your front door.",
                steps=[
                    "Check which device or service is being targeted (look at the port number)",
                    "Immediately change the password for that device/service to something strong",
                    "If possible, temporarily disable remote access to the affected device",
                    "Check if the attacker IP ({source}) has succeeded - look for any unauthorized changes"
                ],
                severity_assessment="Critical - Act Now" if severity == 'critical' else "Needs Attention",
                estimated_risk="If successful, the attacker could take control of your device, steal data, or use it to attack others.",
                prevention_tips=[
                    "Use passwords with 12+ characters, including numbers and symbols",
                    "Enable two-factor authentication (2FA) wherever possible",
                    "Consider disabling remote access if you don't need it",
                    "Use a password manager to generate strong, unique passwords"
                ],
                technical_details="Multiple failed authentication attempts detected. Likely automated password guessing attack.",
                provider='fallback'
            ),
            
            'sql_injection': AIResponse(
                success=True,
                explanation=f"Someone is trying to trick a web application on your network into revealing private data. They're sending specially crafted messages that could let them read, modify, or delete database information.",
                steps=[
                    "Identify which web service or application is being targeted",
                    "If you're running a website or web application, update it immediately",
                    "Check if any data has been accessed or modified",
                    "Block the source IP ({source}) in your firewall if possible"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Attackers could steal usernames, passwords, personal data, or take over entire systems.",
                prevention_tips=[
                    "Keep all web applications and plugins updated",
                    "Use a web application firewall (WAF) if running public services",
                    "Never expose development or admin panels to the internet"
                ],
                technical_details="SQL injection payload detected in HTTP traffic. Common web application attack vector.",
                provider='fallback'
            ),
            
            'xss': AIResponse(
                success=True,
                explanation=f"Someone is trying to inject malicious code into a website or web app on your network. If successful, they could steal login cookies, redirect users, or display fake content.",
                steps=[
                    "Identify which website or application is being targeted",
                    "Update the affected web application to the latest version",
                    "Clear your browser cookies and cache as a precaution",
                    "If you manage the website, review and sanitize all user inputs"
                ],
                severity_assessment="Needs Attention",
                estimated_risk="Could lead to stolen login sessions, phishing attacks, or malware distribution through your site.",
                prevention_tips=[
                    "Keep web applications updated",
                    "Use Content Security Policy (CSP) headers",
                    "Never trust user input - always validate and sanitize"
                ],
                technical_details="Cross-Site Scripting (XSS) payload detected. JavaScript injection attempt.",
                provider='fallback'
            ),
            
            'dns_tunneling': AIResponse(
                success=True,
                explanation=f"A device on your network ({source}) might be secretly sending data out using DNS queries. It's like someone hiding messages inside normal mail - the traffic looks innocent but carries hidden information.",
                steps=[
                    "Identify the device at IP address {source}",
                    "Run a malware scan on that device immediately",
                    "Check for unusual programs or browser extensions",
                    "Monitor the device's internet activity for unusual connections"
                ],
                severity_assessment="Needs Attention",
                estimated_risk="This could indicate malware exfiltrating your data, or a compromised device communicating with attackers.",
                prevention_tips=[
                    "Keep all devices updated with security patches",
                    "Use reputable antivirus software",
                    "Be careful about downloading programs from unknown sources"
                ],
                technical_details="Suspicious DNS query patterns detected. Possible data exfiltration via DNS.",
                provider='fallback'
            ),
            
            'arp_spoofing': AIResponse(
                success=True,
                explanation=f"A device is trying to intercept network traffic by pretending to be your router. This is like someone redirecting your mail to their address so they can read it before passing it on.",
                steps=[
                    "Check your router's ARP table for duplicate MAC addresses",
                    "Identify any unauthorized devices on your network",
                    "Restart your router to clear the ARP cache",
                    "Consider using static ARP entries for critical devices"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="All your unencrypted network traffic could be intercepted, including passwords, emails, and personal data.",
                prevention_tips=[
                    "Use HTTPS websites whenever possible",
                    "Consider using a VPN on untrusted networks",
                    "Enable ARP inspection on enterprise routers if available"
                ],
                technical_details="ARP spoofing/poisoning detected. Man-in-the-middle attack in progress.",
                provider='fallback'
            ),
            
            'land_attack': AIResponse(
                success=True,
                explanation=f"Someone is sending malformed network packets designed to crash or freeze devices. The packets have impossible addresses that confuse network equipment.",
                steps=[
                    "Your firewall or router may have already blocked this attack",
                    "Restart any devices that seem slow or unresponsive",
                    "Update your router's firmware to patch vulnerabilities",
                    "Block the source IP if attacks continue"
                ],
                severity_assessment="Moderate Concern",
                estimated_risk="Older devices might crash or become unresponsive. Modern systems are usually protected.",
                prevention_tips=[
                    "Keep all network equipment firmware updated",
                    "Use a modern router with built-in attack protection"
                ],
                technical_details="LAND attack detected - packets with identical source and destination addresses.",
                provider='fallback'
            ),
            
            'command_injection': AIResponse(
                success=True,
                explanation=f"Someone is trying to run system commands through a web application. If successful, they could take complete control of the server.",
                steps=[
                    "Identify which web service is being targeted",
                    "Update the application immediately",
                    "Check server logs for successful command execution",
                    "Block the attacker IP ({source}) in your firewall"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Complete system compromise possible. Attacker could access all data, install malware, or use your system for attacks.",
                prevention_tips=[
                    "Never run web applications with root/admin privileges",
                    "Keep all software updated",
                    "Use input validation and sanitization"
                ],
                technical_details="Command injection payload detected in HTTP request. Shell command execution attempt.",
                provider='fallback'
            ),
            
            'ip_spoofing': AIResponse(
                success=True,
                explanation=f"Network packets are arriving with fake or impossible source addresses. This is like receiving letters with fake return addresses - someone is hiding their identity.",
                steps=[
                    "Your firewall should block most spoofed traffic",
                    "Check if any devices on your network are compromised",
                    "Review your router logs for the actual source",
                    "Enable ingress filtering if your router supports it"
                ],
                severity_assessment="Moderate Concern",
                estimated_risk="Spoofed packets are often used to hide the source of attacks or to perform reflection attacks.",
                prevention_tips=[
                    "Enable reverse path filtering on your router",
                    "Keep router firmware updated"
                ],
                technical_details="Packets with spoofed/invalid source IP addresses detected.",
                provider='fallback'
            ),
            
            'path_traversal': AIResponse(
                success=True,
                explanation=f"Someone is trying to access files they shouldn't by manipulating file paths. It's like asking for 'Room 101' but actually trying to get into the manager's office.",
                steps=[
                    "Identify which web application is being targeted",
                    "Check if any sensitive files were accessed",
                    "Update the web application immediately",
                    "Review file permissions on the server"
                ],
                severity_assessment="Needs Attention",
                estimated_risk="Attackers could read configuration files, passwords, or other sensitive data.",
                prevention_tips=[
                    "Never construct file paths from user input",
                    "Run web apps with minimal file permissions",
                    "Keep all software updated"
                ],
                technical_details="Directory traversal attempt detected (../ patterns in request).",
                provider='fallback'
            ),
            
            'c2_beacon': AIResponse(
                success=True,
                explanation=f"A device on your network ({source}) appears to be communicating with a remote command server at regular intervals. This is often a sign of malware that has infected a device and is 'checking in' with its controller.",
                steps=[
                    "Immediately disconnect the device at {source} from your network",
                    "Run a full antivirus/malware scan on the device",
                    "Check for any unauthorized software or browser extensions",
                    "Consider reinstalling the operating system if malware is found",
                    "Change all passwords that were used on that device"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Your device may be under remote control by attackers. They could steal data, spy on you, or use your device to attack others.",
                prevention_tips=[
                    "Keep all software and operating systems updated",
                    "Don't download software from untrusted sources",
                    "Use reputable antivirus software",
                    "Be cautious with email attachments and links"
                ],
                technical_details="Regular callback pattern detected indicating possible Command & Control communication.",
                provider='fallback'
            ),
            
            'ddos': AIResponse(
                success=True,
                explanation=f"Your network is under a distributed attack from multiple sources. Many different computers are flooding your connection to overwhelm it and take it offline.",
                steps=[
                    "Contact your Internet Service Provider (ISP) immediately",
                    "Enable DDoS protection if your router supports it",
                    "Document the attack times and any source IPs for your ISP",
                    "Consider a DDoS protection service if attacks continue"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Your internet connection will slow down or stop working. You may lose access to important online services.",
                prevention_tips=[
                    "Use a router with DDoS protection features",
                    "Consider a DDoS mitigation service for critical systems",
                    "Keep your network infrastructure updated"
                ],
                technical_details="Distributed Denial of Service attack detected - traffic from multiple sources.",
                provider='fallback'
            ),
            
            'arp_flood': AIResponse(
                success=True,
                explanation=f"A device on your network is flooding it with address resolution messages. This can slow down or crash network equipment.",
                steps=[
                    "Identify the device sending the flood (check {source})",
                    "Restart the suspected device",
                    "Check for malware on the device",
                    "Update network device firmware"
                ],
                severity_assessment="Needs Attention",
                estimated_risk="Network slowdown or complete network failure if not addressed.",
                prevention_tips=[
                    "Keep all network devices updated",
                    "Use managed switches with ARP rate limiting",
                    "Monitor network for unusual activity"
                ],
                technical_details="ARP packet flood detected - possible network disruption attempt.",
                provider='fallback'
            ),
            
            'covert_channel': AIResponse(
                success=True,
                explanation=f"Data may be being secretly transferred through an unusual network channel. It's like someone hiding a secret message inside normal-looking mail.",
                steps=[
                    "Identify the device at {source}",
                    "Run malware scans on the suspected device",
                    "Check for unusual programs or browser extensions",
                    "Monitor outbound traffic from the device"
                ],
                severity_assessment="Needs Attention",
                estimated_risk="Sensitive data could be leaking from your network without you knowing.",
                prevention_tips=[
                    "Use network monitoring tools",
                    "Keep security software updated",
                    "Restrict unnecessary network access"
                ],
                technical_details="Suspicious covert channel communication patterns detected.",
                provider='fallback'
            ),
            
            'malformed_packet': AIResponse(
                success=True,
                explanation=f"Strange, incorrectly-formatted network messages are being sent to your network. These can sometimes crash network equipment or are used to probe for vulnerabilities.",
                steps=[
                    "Monitor if this continues or was a one-time event",
                    "Update your router's firmware to the latest version",
                    "Check if any devices are malfunctioning",
                    "Block the source IP if attacks persist"
                ],
                severity_assessment="Moderate Concern",
                estimated_risk="Could indicate an attacker probing your network, or just a malfunctioning device.",
                prevention_tips=[
                    "Keep router firmware updated",
                    "Enable packet validation on your router if available",
                    "Monitor for repeated occurrences"
                ],
                technical_details="Malformed network packets detected - potential probe or attack attempt.",
                provider='fallback'
            ),
            
            'session_hijack': AIResponse(
                success=True,
                explanation=f"Someone is attempting to take over an existing connection on your network. This is like someone intercepting your phone call and pretending to be you - they're trying to inject themselves into your network sessions.",
                steps=[
                    "Immediately check for unfamiliar devices on your network",
                    "Disconnect any devices you don't recognize",
                    "Change passwords for all important accounts (email, banking, social media)",
                    "Run antivirus/malware scans on all devices",
                    "Restart your router to clear any compromised sessions"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Attackers could intercept your data, steal login sessions, or take control of your accounts. This is a serious active attack.",
                prevention_tips=[
                    "Use HTTPS websites whenever possible (look for the padlock)",
                    "Enable two-factor authentication on all accounts",
                    "Use a VPN for sensitive browsing",
                    "Keep all devices and software updated"
                ],
                technical_details="TCP session injection detected - packets with data sent to non-established connections, indicating man-in-the-middle or session hijacking attempt.",
                provider='fallback'
            ),
            
            'data_exfiltration': AIResponse(
                success=True,
                explanation=f"A large amount of data is being sent from your network to an external location. This could mean your files, photos, or personal information are being stolen and uploaded to an attacker's server.",
                steps=[
                    "Identify the device at {source} sending the data",
                    "Immediately disconnect that device from your network",
                    "Run a full malware scan on the device",
                    "Check for unfamiliar programs or browser extensions",
                    "Review what data might have been accessed (documents, photos, passwords)"
                ],
                severity_assessment="Critical - Act Now",
                estimated_risk="Your personal files, photos, passwords, or sensitive documents may be being stolen. Financial information could be compromised.",
                prevention_tips=[
                    "Install reputable antivirus software on all devices",
                    "Be careful about what programs you download",
                    "Use a firewall to monitor outgoing connections",
                    "Regularly back up important files to a secure location"
                ],
                technical_details="Large outbound data transfer detected - possible data exfiltration to external server.",
                provider='fallback'
            ),
        }
        
        # Return specific response or generic one
        print(f"[AI] Available types: {list(responses.keys())}")
        print(f"[AI] Looking for: '{alert_type}' - Match: {alert_type in responses}")
        
        if alert_type in responses:
            print(f"[AI] Found specific response for '{alert_type}'")
            response = responses[alert_type]
            # Format source IP into the steps
            response.steps = [step.format(source=source) for step in response.steps]
            return response
        
        # Generic fallback for unknown alert types
        print(f"[AI] No specific response for '{alert_type}', using GENERIC fallback")
        return AIResponse(
            success=True,
            explanation=f"A security event was detected from {source}. While the exact nature isn't immediately clear, it's worth investigating to ensure your network remains secure.",
            steps=[
                f"Check if you recognize the device or IP address ({source})",
                "Review recent network activity for anything unusual",
                "Ensure all your devices have updated security software",
                "If concerned, restart your router and change your Wi-Fi password"
            ],
            severity_assessment="Moderate Concern" if severity not in ['critical', 'high'] else "Needs Attention",
            estimated_risk="Unknown threats should be investigated to rule out potential security issues.",
            prevention_tips=[
                "Keep all devices and software updated",
                "Use strong, unique passwords",
                "Regularly review devices connected to your network"
            ],
            technical_details=context.get('description', 'No additional technical details available.'),
            provider='fallback'
        )
    
    def explain_term(self, term: str) -> Dict:
        """
        Explain a technical security term in simple language
        """
        explanations = {
            'port scan': {
                'simple': "Someone is checking which 'doors' (ports) are open on your network",
                'analogy': "Like a burglar testing all your doors and windows to see which ones are unlocked",
                'risk': "Usually a first step before an actual attack"
            },
            'syn flood': {
                'simple': "Overwhelming a computer with connection requests to make it unavailable",
                'analogy': "Like thousands of people calling your phone at once so no real calls can get through",
                'risk': "Can make your internet slow or unavailable"
            },
            'ddos': {
                'simple': "An attack where many computers flood your network with traffic",
                'analogy': "Like a flash mob blocking your driveway so you can't leave or receive deliveries",
                'risk': "Can knock your entire network offline"
            },
            'brute force': {
                'simple': "Trying thousands of passwords to guess the right one",
                'analogy': "Like trying every possible key on a keyring until one fits your lock",
                'risk': "If successful, attackers gain access to your accounts"
            },
            'sql injection': {
                'simple': "Tricking a website into revealing private database information",
                'analogy': "Like asking a store clerk a trick question that makes them reveal the safe combination",
                'risk': "Can expose all stored usernames, passwords, and personal data"
            },
            'xss': {
                'simple': "Injecting malicious code into websites that runs in visitors' browsers",
                'analogy': "Like someone replacing a store's sign with one that pickpockets customers who read it",
                'risk': "Can steal login sessions and personal information"
            },
            'arp spoofing': {
                'simple': "Pretending to be the router to intercept network traffic",
                'analogy': "Like someone posing as a mail carrier to read your letters before delivering them",
                'risk': "All unencrypted data can be seen by the attacker"
            },
            'dns tunneling': {
                'simple': "Hiding data inside normal-looking DNS requests",
                'analogy': "Like writing secret messages in invisible ink on ordinary postcards",
                'risk': "Often used by malware to secretly send your data to attackers"
            },
            'firewall': {
                'simple': "A security system that controls what traffic can enter and leave your network",
                'analogy': "Like a security guard at a building entrance who checks everyone coming in and out",
                'risk': "Without one, your network is more vulnerable to attacks"
            },
            'ip address': {
                'simple': "A unique number that identifies each device on a network",
                'analogy': "Like a phone number or street address for your computer",
                'risk': "Knowing your IP address can help attackers target you"
            },
        }
        
        term_lower = term.lower().replace('-', ' ').replace('_', ' ')
        
        if term_lower in explanations:
            return {
                'term': term,
                'found': True,
                **explanations[term_lower]
            }
        
        return {
            'term': term,
            'found': False,
            'simple': f"'{term}' is a technical security term. Ask for more details!",
            'analogy': "No analogy available",
            'risk': "Unknown"
        }
    
    def get_network_health_summary(self, stats: Dict) -> Dict:
        """
        Generate a plain-language summary of network health
        """
        total_alerts = stats.get('total_alerts', 0)
        critical = stats.get('critical_alerts', 0)
        high = stats.get('high_alerts', 0)
        
        if critical > 0:
            status = "[CRITICAL] Issues Detected"
            message = f"Your network has {critical} critical security issue{'s' if critical > 1 else ''} that need{'s' if critical == 1 else ''} immediate attention."
            action = "Review the critical alerts below and take action as soon as possible."
        elif high > 0:
            status = "[WARNING] Attention Needed"
            message = f"Your network has {high} high-priority alert{'s' if high > 1 else ''} that should be reviewed."
            action = "Check the alerts when you have a moment to ensure everything is secure."
        elif total_alerts > 0:
            status = "[INFO] Minor Concerns"
            message = f"Your network detected {total_alerts} event{'s' if total_alerts > 1 else ''}, but nothing critical."
            action = "You can review these alerts at your convenience."
        else:
            status = "[OK] All Clear"
            message = "Your network looks healthy! No security threats detected."
            action = "Keep up the good work! Regular monitoring helps keep you safe."
        
        return {
            'status': status,
            'message': message,
            'action': action,
            'stats': {
                'total_alerts': total_alerts,
                'critical': critical,
                'high': high,
                'medium': stats.get('medium_alerts', 0)
            }
        }


# Singleton instance
_ai_assistant: Optional[AISecurityAssistant] = None


def get_ai_assistant() -> AISecurityAssistant:
    """Get or create the AI assistant singleton"""
    global _ai_assistant
    if _ai_assistant is None:
        _ai_assistant = AISecurityAssistant()
    return _ai_assistant


def init_ai_assistant(provider: str = None, api_key: str = None) -> AISecurityAssistant:
    """Initialize the AI assistant with specific settings"""
    global _ai_assistant
    _ai_assistant = AISecurityAssistant(provider=provider, api_key=api_key)
    return _ai_assistant
