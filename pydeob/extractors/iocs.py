import re
from typing import List
from pydeob.models import IOC

class IOCExtractor:
    # Regex patterns for various IOCs
    PATTERNS = {
        "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "domain": r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "telegram": r't\.me/[A-Za-z0-9_]{5,}',
        "discord_webhook": r'discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
        "btc_wallet": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "eth_wallet": r'\b0x[a-fA-F0-9]{40}\b',
    }

    def extract(self, text: str) -> List[IOC]:
        results = []
        for ioc_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                value = match.group()
                # Basic validation for IP
                if ioc_type == "ip":
                    parts = value.split('.')
                    if any(int(p) > 255 for p in parts):
                        continue
                
                results.append(IOC(type=ioc_type, value=value))
        
        # Remove duplicates
        unique_results = []
        seen = set()
        for ioc in results:
            if (ioc.type, ioc.value) not in seen:
                unique_results.append(ioc)
                seen.add((ioc.type, ioc.value))
                
        return unique_results
