import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from groq import Groq
import openai

@dataclass
class AttackContext:
    """Structured representation of an attack for AI analysis"""
    attack_type: str
    payload: str
    source_ip: str
    timestamp: str
    threat_score: float
    additional_context: Dict

class SecurityAICompanion:
    def __init__(self, api_provider="groq", api_key=None):
        self.api_provider = api_provider
        self.api_key = api_key
        
        # Initialize AI client lazily when methods are called to allow dynamic API key passing
        self.client = None
        if api_provider == "groq":
            self.model = "llama-3.1-70b-versatile"
        else:
            self.model = "gpt-4"
        
        # Load attack knowledge base
        self.attack_db = self._load_attack_knowledge()
        
    def _initialize_client(self, api_key):
        if self.api_provider == "groq" and api_key:
            return Groq(api_key=api_key)
        elif self.api_provider == "openai" and api_key:
            openai.api_key = api_key
            return openai
        return None

    def _load_attack_knowledge(self):
        """Load comprehensive attack pattern database"""
        return {
            "sqli": {
                "name": "SQL Injection",
                "indicators": ["'", "OR 1=1", "UNION SELECT", "'; DROP TABLE"],
                "definition": "SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It allows an attacker to view data that they are not normally able to retrieve.",
                "intent": "Database manipulation, data exfiltration, authentication bypass",
                "real_world": "In 2023, the MOVEit Transfer data breach utilized SQL injection to steal data from hundreds of organizations, affecting millions of individuals globally. In 2021, a major SQLi vulnerability was found in the WooCommerce plugin for WordPress, impacting millions of sites.",
                "mitigation": "Parameterized queries, input validation, WAF rules"
            },
            "xss": {
                "name": "Cross-Site Scripting",
                "indicators": ["<script>", "javascript:", "onerror=", "alert("],
                "definition": "Cross-Site Scripting (XSS) is a vulnerability where an attacker injects malicious client-side scripts into web pages viewed by other users. This can be used to bypass access controls or steal sessions.",
                "intent": "Session hijacking, credential theft, defacement",
                "real_world": "In 2023, a significant XSS vulnerability was discovered in the popular Zimbra collaboration suite, allowing attackers to steal email data. In 2021, multiple XSS flaws were found and exploited in Microsoft Exchange Server.",
                "mitigation": "Content Security Policy, output encoding, sanitization"
            },
            "ssrf": {
                "name": "Server-Side Request Forgery",
                "indicators": ["http://localhost", "file://", "169.254.169.254"],
                "definition": "Server-Side Request Forgery (SSRF) is a flaw where an attacker can abuse functionality on the server to read or update internal resources. The attacker can supply a URL which the server will fetch.",
                "intent": "Internal network scanning, cloud metadata access",
                "real_world": "In 2021, the massive Microsoft Exchange Server data breaches (ProxyLogon) chained SSRF vulnerabilities to achieve remote code execution. In 2024, Ivanti Connect Secure VPNs were breached using an SSRF vulnerability.",
                "mitigation": "URL allowlisting, disable unnecessary protocols"
            },
            "xxe": {
                "name": "XML External Entity",
                "indicators": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file:///"],
                "definition": "XML External Entity (XXE) is a vulnerability that abuses a widely available but rarely used feature of XML parsers to interfere with an application's processing of XML data. It allows an attacker to view files on the application server filesystem.",
                "intent": "File disclosure, SSRF, denial of service",
                "real_world": "While XXE instances are decreasing due to safer defaults, in 2021 vulnerabilities were found in numerous enterprise Java applications that still processed XML external entities unsafely, leading to sensitive file disclosures across corporate networks.",
                "mitigation": "Disable DTD processing, use JSON instead of XML"
            },
            "csrf": {
                "name": "Cross-Site Request Forgery",
                "indicators": ["<form", "auto-submit", "hidden fields"],
                "definition": "Cross-Site Request Forgery (CSRF) is a vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy.",
                "intent": "Unauthorized state-changing operations",
                "real_world": "In 2022, high-severity CSRF vulnerabilities were discovered in several popular routers and IoT devices, allowing attackers to change admin passwords if a logged-in user visited a malicious website.",
                "mitigation": "CSRF tokens, SameSite cookies, check Origin header"
            },
            "phishing": {
                "name": "Phishing Attack",
                "indicators": ["typosquatting", "lookalike domains", "urgent action", "login", "verify"],
                "definition": "Phishing is a cyber attack that uses disguised email as a weapon. The goal is to trick the email recipient into believing that the message is something they want or need, and clicking a link or downloading an attachment.",
                "intent": "Credential harvesting, malware distribution",
                "real_world": "In 2022, the Twilio breach occurred when employees were tricked by SMS phishing (smishing) into handing over their credentials, leading to a compromise of customer data. In 2023, phishing campaigns heavily targeted MGM Resorts, leading to a massive ransomware incident.",
                "mitigation": "Security awareness training, email filtering, MFA"
            },
            "log4j": {
                "name": "Log4Shell (CVE-2021-44228)",
                "indicators": ["${jndi:ldap", "${jndi:rmi", "${env:", "${sys:"],
                "definition": "Log4Shell is a critical vulnerability in the widely-used Log4j logging framework. It allows an attacker to execute arbitrary code on a system simply by getting the system to log a specially crafted string.",
                "intent": "Remote code execution, system compromise",
                "real_world": "Discovered in late 2021, Log4Shell caused a global crisis affecting millions of servers. Companies like VMware, Amazon, and Cloudflare rushed to patch systems as nation-state actors and ransomware gangs actively exploited it across the internet.",
                "mitigation": "Patch to 2.17.1+, WAF rules, JVM flags"
            }
        }
    
    def analyze_attack(self, attack_context: AttackContext, api_key: str) -> Dict:
        """Comprehensive attack analysis with AI reasoning"""
        
        # First, try to identify attack pattern
        attack_classification = self._classify_attack(attack_context.payload)
        
        # Build context-aware prompt
        prompt = self._build_analysis_prompt(attack_context, attack_classification)
        
        client = self._initialize_client(api_key)
        if not client:
             return {"error": "API Key not provided or invalid for analysis."}
             
        analysis = ""
        try:
            if self.api_provider == "groq":
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": self._get_system_prompt()
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.7,
                    max_tokens=2000
                )
                analysis = response.choices[0].message.content
            else:
                # OpenAI implementation
                response = openai.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7
                )
                analysis = response.choices[0].message.content
        except Exception as e:
             return {"error": f"Failed to perform AI analysis: {str(e)}"}
             
        # Structure the response
        return {
            "attack_type": attack_classification.get("type", "unknown"),
            "confidence": attack_classification.get("confidence", 0),
            "detailed_analysis": analysis,
            "quick_facts": self._extract_quick_facts(attack_classification),
            "recommended_actions": self._get_recommendations(attack_classification),
            "investigation_queries": self._generate_hunt_queries(attack_context)
        }
    
    def _classify_attack(self, payload: str) -> Dict:
        """Classify attack type based on payload patterns"""
        payload_lower = payload.lower()
        
        best_confidence = 0
        best_match = {"type": "unknown", "confidence": 0}

        for attack_key, attack_info in self.attack_db.items():
            confidence = 0
            matches = []
            
            for indicator in attack_info["indicators"]:
                if indicator.lower() in payload_lower:
                    confidence += 25
                    matches.append(indicator)
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = {
                    "type": attack_key,
                    "name": attack_info["name"],
                    "confidence": min(confidence, 100),
                    "matched_patterns": matches,
                    "knowledge": attack_info
                }
                
        return best_match
    
    def _get_system_prompt(self) -> str:
        """System prompt for AI companion"""
        return '''You are an expert Security Operations Center (SOC) analyst and investigation companion.
        
Your role is to:
• Analyze security threats with deep technical expertise
• Explain attacks in clear, professional language (not dumbed down)
• Provide actionable intelligence for investigation
• Share real-world context and implications
• Think like a threat hunter, not a teacher

You work alongside security professionals, researchers, and students who have foundational knowledge.
Communicate as a peer, not a tutor. Be direct, technical when needed, and always investigation-focused.

When analyzing attacks:
• Explain the attacker's likely intent and goals
• Describe the technical mechanism of exploitation
• Provide real-world examples and impact assessment
• Suggest specific investigation steps and queries
• Consider attack chains and lateral movement possibilities'''
    
    def _build_analysis_prompt(self, context: AttackContext, classification: Dict) -> str:
        """Build context-aware analysis prompt"""
        
        attack_name = classification.get("knowledge", {}).get("name", "Unknown Attack")
        
        prompt = f"""Analyze this security incident as my SOC investigation partner:

Attack Detected: {attack_name}
Confidence: {classification.get('confidence', 0)}%
Timestamp: {context.timestamp}
Source IP: {context.source_ip}
Threat Score: {context.threat_score}/10

Payload Sample:
`
{context.payload[:500]}
`

Matched Patterns: {', '.join(classification.get('matched_patterns', []))}

As my investigation companion, provide:

1. Attacker Intent Analysis: What is the attacker trying to achieve? Consider both immediate and strategic goals.
2. Technical Breakdown: How does this specific payload work? Break down the exploitation mechanism.
3. Attack Chain Context: Where does this fit in a potential attack chain? What might come before/after?
4. Investigation Priority: Given the threat score of {context.threat_score}, how should we prioritize this?
5. Hunt Queries: Specific Elasticsearch or SQL queries to find related activity.
6. Defensive Gaps: What security controls failed or are missing?

Remember: I'm a security professional, not a student. Be direct and technical. Use Markdown formatting."""
        
        return prompt
    
    def _extract_quick_facts(self, classification: Dict) -> Dict:
        """Extract quick reference facts"""
        knowledge = classification.get("knowledge", {})
        return {
            "attack_family": knowledge.get("name", "Unknown"),
            "typical_intent": knowledge.get("intent", "Unknown"),
            "famous_incident": knowledge.get("real_world", "No notable examples"),
            "primary_mitigation": knowledge.get("mitigation", "Standard security practices")
        }
    
    def _get_recommendations(self, classification: Dict) -> List[str]:
        """Get specific recommendations based on attack type"""
        attack_type = classification.get("type", "unknown")
        
        recommendations_map = {
            "sqli": [
                "Review database query logs for unusual UNION/SELECT patterns",
                "Check for data exfiltration via DNS or timing channels",
                "Audit database user permissions and recent privilege changes",
                "Enable SQL query logging if not already active"
            ],
            "xss": [
                "Search for similar payloads targeting other endpoints",
                "Review Content-Security-Policy headers on affected pages",
                "Check for stored XSS possibilities in user-generated content",
                "Analyze JavaScript error logs for execution attempts"
            ],
            "ssrf": [
                "Monitor for internal network scanning patterns",
                "Check cloud metadata endpoints access (169.254.169.254)",
                "Review egress traffic to unusual internal IPs",
                "Audit service-to-service authentication mechanisms"
            ],
            "phishing": [
                "Review email flow and DMARC failures",
                "Block malicious domains at perimeter",
                "Force password resets for affected users",
                "Analyze proxy logs for clicked links"
            ]
        }
        
        return recommendations_map.get(attack_type, [
            "Investigate source IP reputation and historical activity",
            "Check for similar patterns in last 24 hours",
            "Review authentication logs for this source",
            "Consider implementing rate limiting"
        ])
    
    def _generate_hunt_queries(self, context: AttackContext) -> List[Dict]:
        """Generate threat hunting queries for Elasticsearch"""
        queries = [
            {
                "description": "Find all activity from this source IP",
                "query": f'source_ip:"{context.source_ip}" AND timestamp:[now-24h TO now]'
            },
            {
                "description": "Search for similar attack patterns",
                "query": f'attack_type:"{context.attack_type}" AND threat_score:>={context.threat_score - 1}'
            },
            {
                "description": "Find obfuscated variants",
                "query": f'obfuscation_score:>=0.5 AND attack_type:"{context.attack_type}"'
            }
        ]
        return queries
    
    def conversational_response(self, messages: List[Dict], api_key: str, context: Optional[Dict] = None) -> str:
        """Handle conversational queries about security topics directly using Groq API"""
        
        client = self._initialize_client(api_key)
        
        if not client:
             return self._offline_heuristic_response(messages[-1].get("content", ""), context)
             
        # Extract the latest user message
        user_message = messages[-1].get("content", "").lower().strip() if messages else ""
        
        prompt = f"""As the Sentinel AI Security Investigation Companion, respond to this query from a security professional.

{f"Current Investigation Context (JSON): {json.dumps(context, indent=2)}" if context else "No active investigation context."}

Provide a technical but accessible response that helps with investigation or analysis.
Focus on practical, actionable information rather than basic explanations. Use Markdown formatting.
"""

        # Format messages for Groq
        formatted_messages = [{"role": "system", "content": self._get_system_prompt() + "\\n\\n" + prompt}]
        
        # Add history
        for m in messages[-20:]:  
            formatted_messages.append({
                "role": m.get("role", "user"),
                "content": str(m.get("content", ""))
            })

        try:
             if self.api_provider == "groq":
                 response = client.chat.completions.create(
                     model=self.model,
                     messages=formatted_messages,
                     temperature=0.7,
                     max_tokens=1500
                 )
                 return response.choices[0].message.content
             else:
                 response = openai.ChatCompletion.create(
                     model=self.model,
                     messages=formatted_messages,
                     temperature=0.7
                 )
                 return response.choices[0].message.content
        except Exception as e:
            print(f"[ERROR] API failed: {e}")
            return self._offline_heuristic_response(user_message, context)
            
    def _offline_heuristic_response(self, user_message: str, context: Optional[Dict] = None) -> str:
        """Fallback method when API is unavailable"""
        user_msg_lower = user_message.lower().strip()
        
        # End of free trial disclaimer
        trial_disclaimer = "\n\n*(Note: Your free trial for live AI analysis has hit its limit. Please provide a Groq API Key for full context-aware analysis.)*"
        
        # Handle greetings
        greetings = ["hai", "hello", "hy", "hlo", "hi", "hey", "good morning", "good evening", "how are you"]
        if any(user_msg_lower == greet or user_msg_lower.startswith(greet + " ") for greet in greetings):
            return "Hello! I am your Security Companion. I can currently help you understand various attack types like SQLi, XSS, SSRF, and Phishing. What would you like to learn about?" + trial_disclaimer
            
        # Handle simplification / 'explain again' requests
        if "don't understand" in user_msg_lower or "explain again" in user_msg_lower or "simplify" in user_msg_lower or "dumb it down" in user_msg_lower:
            # Try to figure out what they want simplified
            for attack_key, attack_info in self.attack_db.items():
                if attack_key in user_msg_lower or attack_info["name"].lower() in user_msg_lower:
                    return f"No problem, let me simplify **{attack_info['name']}**.\n\nImagine a bouncer at a club checking IDs. If the bouncer just lets anyone in who says 'I belong here' without checking the ID properly, that's similar to this vulnerability. Attackers exploit trust to trick the application into doing things it shouldn't, like giving away data or running bad commands. Does that make more sense?" + trial_disclaimer
            return "Sure, I can try to explain things more simply! But you need to tell me which attack you want me to re-explain (for example, 'explain SQLi again')." + trial_disclaimer

        # Simple heuristic pattern matching based on DB
        for attack_key, attack_info in self.attack_db.items():
            if attack_key in user_msg_lower or attack_info["name"].lower() in user_msg_lower or any(ind.lower() in user_msg_lower for ind in attack_info["indicators"]):
                
                # Check for specific questions
                if "real world" in user_msg_lower or "example" in user_msg_lower or "happened" in user_msg_lower or "company" in user_msg_lower or "companies" in user_msg_lower:
                    return f"### Real-World Example: {attack_info['name']}\n\n{attack_info['real_world']}" + trial_disclaimer
                    
                if "what" in user_msg_lower or "explain" in user_msg_lower or "define" in user_msg_lower:
                    return f"### {attack_info['name']}\n\n{attack_info['definition']}" + trial_disclaimer
                    
                if "how" in user_msg_lower or "prevent" in user_msg_lower or "mitigate" in user_msg_lower or "stop" in user_msg_lower:
                    return f"### Preventing {attack_info['name']}\n\n**Mitigation strategies:** {attack_info['mitigation']}" + trial_disclaimer
                
                # If they just ask the name or ask broadly
                reply = f"### {attack_info['name']} Overview\n\n"
                reply += f"{attack_info['definition']}\n\n"
                reply += f"**Indicators**: {', '.join(attack_info['indicators'])}\n"
                reply += f"**Attacker Intent**: {attack_info['intent']}\n"
                reply += f"**Mitigation**: {attack_info['mitigation']}"
                reply += trial_disclaimer
                return reply
                 
        if context:
            return "I cannot analyze the current payload dynamically without an API key. You should review the source IP and look for similar patterns in your SIEM." + trial_disclaimer
        
        return "I am ready to assist. Please ask a specific question. For example, ask 'what is sqli?', 'real world example for xss', or 'explain ssrf again'." + trial_disclaimer
