"""
OSINT Correlation Analyzer
GitHub mining, LinkedIn inference, WHOIS correlation
"""

from datetime import datetime
import re

class OSINTAnalyzer:
    """Analyzes OSINT correlation vectors"""
    
    def analyze_github_timing(self, commit_times, operational_times):
        """
        Analyze correlation between GitHub commits and operational activity
        
        Args:
            commit_times: List of GitHub commit timestamps
            operational_times: List of operational activity timestamps
        
        Returns:
            dict with correlation coefficient and attribution weight
        """
        # Calculate time deltas
        deltas = []
        for i,git_time in enumerate(commit_times):
            if i < len(operational_times):
                delta = abs((git_time - operational_times[i]).total_seconds() / 60)
                deltas.append(delta)
        
        avg_delta = sum(deltas) / len(deltas) if deltas else 0
        
        # High correlation if commits within 30 minutes of ops
        if avg_delta < 30:
            correlation = 0.95
            risk = 'CRITICAL'
        elif avg_delta < 120:
            correlation = 0.75
            risk = 'HIGH'
        else:
            correlation = 0.4
            risk = 'MEDIUM'
        
        aw = 1.0 * 1.0 * correlation  # V=1.0 (public), R=1.0 (permanent)
        
        return {
            'avg_time_delta_minutes': avg_delta,
            'correlation_coefficient': correlation,
            'visibility': 1.0,
            'retention': 1.0,
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Randomize commit times ±6 hours minimum'
        }
    
    def analyze_linkedin_team(self, employees, operational_skills):
        """
        Infer team composition from LinkedIn data
        """
        skill_matches = len(set(employees) & set(operational_skills))
        
        if skill_matches > 5:
            aw = 0.8
            risk = 'HIGH'
        elif skill_matches > 2:
            aw = 0.5
            risk = 'MEDIUM'
        else:
            aw = 0.3
            risk = 'LOW'
        
        return {
            'matched_skills': skill_matches,
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Compartmentalize: separate operational from public identities'
        }
    
    def analyze_whois_correlation(self, domains):
        """
        Check WHOIS correlation across domains
        """
        # Simplified: check if same registrar, nameservers
        registrars = set()
        nameservers = set()
        
        for domain in domains:
            registrars.add(domain.get('registrar', 'unknown'))
            ns = domain.get('nameservers', [])
            for server in ns:
                nameservers.add(server)
        
        # High correlation if same provider infrastructure
        if len(registrars) == 1 and len(nameservers) <=2:
            aw = 0.85
            risk = 'CRITICAL'
        elif len(registrars) <= 2:
            aw = 0.6
            risk = 'HIGH'
        else:
            aw = 0.3
            risk = 'MEDIUM'
        
        return {
            'unique_registrars': len(registrars),
            'unique_nameservers': len(nameservers),
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Use diverse registrars and DNS providers'
        }
