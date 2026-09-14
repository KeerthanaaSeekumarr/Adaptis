from elasticsearch import Elasticsearch
from datetime import datetime
import hashlib
import json

class SentinelElasticEngine:
    def __init__(self):
        # Allow disabling Elasticsearch dependency gracefully if the container isn't running
        self.enabled = False
        try:
            self.es = Elasticsearch(
                ['http://localhost:9200'],
                request_timeout=3
            )
            # Explicitly check connection
            if self.es.ping():
                self.enabled = True
                self.create_threat_index()
                print("[+] Connected to Elasticsearch locally.")
            else:
                print("[-] Elasticsearch ping failed. Running without ELK Stack features.")
        except Exception as e:
            print(f"[-] Could not connect to Elasticsearch: {e}. Running without ELK Stack features.")
    
    def create_threat_index(self):
        """Create optimized index for security events"""
        index_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "attack_type": {"type": "keyword"},
                    "payload": {"type": "text", "analyzer": "standard"},
                    "payload_hash": {"type": "keyword"},
                    "obfuscation_score": {"type": "float"},
                    "threat_score": {"type": "float"},
                    "ml_confidence": {"type": "float"},
                    "attack_intent": {"type": "keyword"},
                    "decoded_payload": {"type": "text"},
                    "geolocation": {"type": "geo_point"},
                    "analyst_notes": {"type": "text"},
                    "remediation_status": {"type": "keyword"}
                }
            }
        }
        
        try:
            if not self.es.indices.exists(index="sentinel-threats"):
                self.es.indices.create(index="sentinel-threats", body=index_mapping)
        except Exception as e:
            print(f"[-] Could not create ES index: {e}")
    
    def index_threat(self, threat_data):
        """Index a detected threat with deobfuscation analysis"""
        if not self.enabled:
            # Attempt to reconnect if previously failed
            try:
                if self.es.ping():
                    self.enabled = True
                    self.create_threat_index()
                    print("[+] Reconnected to Elasticsearch locally.")
                else:
                    return None
            except Exception:
                return None
            
        # Add obfuscation detection
        threat_data['obfuscation_score'] = self.calculate_obfuscation(
            threat_data.get('payload', '')
        )
        
        # Hash the payload for duplicate detection
        threat_data['payload_hash'] = hashlib.sha256(
            str(threat_data.get('payload', '')).encode()
        ).hexdigest()
        
        # Add timestamp if missing
        if 'timestamp' not in threat_data:
            threat_data['timestamp'] = datetime.utcnow().isoformat() + "Z"
            
        try:
            # Index the document
            response = self.es.index(
                index="sentinel-threats",
                document=threat_data
            )
            return response['_id']
        except Exception as e:
            print(f"[-] Error indexing into ES: {e}")
            return None
    
    def calculate_obfuscation(self, payload):
        """Detect obfuscation techniques"""
        score = 0
        if not payload:
            return 0.0
            
        payload_str = str(payload)
        
        # Check for base64 encoding
        if any(pattern in payload_str for pattern in ['==', 'base64', 'atob']):
            score += 0.3
        
        # Check for URL encoding abuse
        if payload_str.count('%') > 10:
            score += 0.3
        
        # Check for unicode/hex encoding
        if any(pattern in payload_str for pattern in ['\\x', '\\u', '&#x']):
            score += 0.2
        
        # Check for string concatenation obfuscation
        if any(pattern in payload_str for pattern in ['+', 'concat', 'join']):
            score += 0.2
            
        return min(score, 1.0)
