"""
APT Operations & SOC Evasion Analyzer
Detects APT-level operational discipline and SOC evasion techniques
"""

import statistics

class APTOperationsAnalyzer:
    """Analyzes APT-level operational patterns"""
    
    def __init__(self):
        self.signals = []
    
    def analyze_operational_discipline(self, campaign_data):
        """
        Assess if entity exhibits APT-level operational security
        
        Args:
            campaign_data: dict with operational metrics
        
        Returns:
            dict with discipline score and indicators
        """
        score = 0
        indicators = []
        
        # Infrastructure turnover
        infra_lifetime = campaign_data.get('infrastructure_lifetime_days', 90)
        if infra_lifetime < 30:
            score += 20
            indicators.append('Rapid infrastructure rotation (< 30 days)')
        elif infra_lifetime < 60:
            score += 10
            indicators.append('Moderate infrastructure rotation(< 60 days)')
        
        # Tool compartmentalization
        tool_uniqueness = campaign_data.get('unique_tools_per_campaign', 0.3)
        if tool_uniqueness > 0.8:
            score += 20
            indicators.append('High tool compartmentalization (>80% unique)')
        elif tool_uniqueness > 0.5:
            score += 10
            indicators.append('Moderate tool uniqueness')
        
        # Timing discipline
        business_hours_activity = campaign_data.get('activity_during_target_hours', 0.5)
        if business_hours_activity > 0.9:
            score += 20
            indicators.append('Strong timing discipline (90% during business hours)')
        elif business_hours_activity > 0.7:
            score += 10
            indicators.append('Moderate timing discipline')
        
        # Cross-campaign overlap (low = better OPSEC)
        overlap = campaign_data.get('cross_campaign_overlap', 0.5)
        if overlap < 0.1:
            score += 20
            indicators.append('No infrastructure reuse across campaigns')
        elif overlap < 0.3:
            score += 10
            indicators.append('Minimal infrastructure overlap')
        
        # Multi-stage deployment
        if campaign_data.get('uses_multistage_payloads', False):
            score += 20
            indicators.append('Multi-stage payload deployment')
        
        # Calculate attribution weight and risk
        if score >= 70:
            classification = 'APT-level (Nation-state)'
            aw = 0.85
            risk = 'CRITICAL'
        elif score >= 50:
            classification = 'Sophisticated actor'
            aw = 0.65
            risk = 'HIGH'
        elif score >= 30:
            classification = 'Intermediate'
            aw = 0.45
            risk = 'MEDIUM'
        else:
            classification = 'Low sophistication'
            aw = 0.25
            risk = 'LOW'
        
        return {
            'discipline_score': score,
            'classification': classification,
            'indicators': indicators,
            'attribution_weight': aw,
            'risk': risk
        }
    
    def detect_lotl_usage(self, process_data):
        """
        Detect Living Off The Land (LOTL) techniques
        """
        lotl_tools = {
            'windows': ['powershell.exe', 'wmic.exe', 'mshta.exe', 'regsvr32.exe', 
                       'rundll32.exe', 'msiexec.exe', 'bitsadmin.exe', 'certutil.exe'],
            'linux': ['bash', 'sh', 'curl', 'wget', 'nc', 'python', 'perl', 'ruby'],
            'macos': ['osascript', 'launchctl', 'bash', 'python', 'ruby']
        }
        
        os_type = process_data.get('os_type', 'windows')
        process_name = process_data.get('process_name', '').lower()
        
        is_lotl = process_name in lotl_tools.get(os_type, [])
        
        if is_lotl:
            # LOTL is stealthy - blends with legitimate admin activity
            return {
                'is_lotl': True,
                'tool': process_name,
                'visibility': 0.5,
                'retention': 0.9,
                'correlation': 0.4,
                'attribution_weight': 0.18,
                'risk': 'LOW',
                'note': 'Blends with legitimate admin activity'
            }
        
        return {'is_lotl': False, 'attribution_weight': 0.6}
    
    def analyze_timing_evasion(self, activity_timestamps, target_timezone='UTC'):
        """
        Analyze if activity timing evades SOC monitoring
        """
        if not activity_timestamps:
            return {'attribution_weight': 0.0}
        
        # Extract hour of day from timestamps
        hours = [ts.hour for ts in activity_timestamps]
        
        # Check if activity concentrated in low-SOC hours (02:00-05:00)
        low_soc_hours = [h for h in hours if 2 <= h <= 5]
        weekend_activity =  [ts for ts in activity_timestamps if ts.weekday() >= 5]
        
        low_soc_ratio = len(low_soc_hours) / len(hours)
        weekend_ratio = len(weekend_activity) / len(activity_timestamps)
        
        if low_soc_ratio > 0.7 or weekend_ratio > 0.5:
            return {
                'timing_evasion': 'HIGH',
                'low_soc_hours_ratio': low_soc_ratio,
                'weekend_ratio': weekend_ratio,
                'visibility': 0.3,
                'retention': 0.9,
                'correlation': 0.5,
                'attribution_weight': 0.14,
                'risk': 'LOW',
                'note': 'Activity concentrated during low-SOC periods'
            }
        
        return {
            'timing_evasion': 'NONE',
            'attribution_weight': 0.5
        }
    
    def calculate_apt_opsec_score(self, metrics):
        """
        Calculate overall APT OPSEC score
        
        Formula: Infrastructure_Turnover × Tool_Compartmentalization × Timing_Discipline × Anti_Forensics
        """
        infra = metrics.get('infrastructure_turnover', 0.5)
        tools = metrics.get('tool_compartmentalization', 0.5)
        timing = metrics.get('timing_discipline', 0.5)
        forensics = metrics.get('anti_forensics', 0.5)
        
        score = infra * tools * timing * forensics
        
        if score > 0.7:
            classification = 'APT-level'
            risk = 'CRITICAL'
        elif score > 0.4:
            classification = 'Sophisticated'
            risk = 'HIGH'
        else:
            classification = 'Basic'
            risk = 'MEDIUM'
        
        return {
            'apt_opsec_score': score,
            'classification': classification,
            'risk': risk,
            'components': {
                'infrastructure_turnover': infra,
                'tool_compartmentalization': tools,
                'timing_discipline': timing,
                'anti_forensics': forensics
            }
        }
