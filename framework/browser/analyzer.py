"""
Browser OPSEC Analyzer
Detects WebRTC leaks, Canvas fingerprinting, and other browser-based attribution vectors
"""

class BrowserAnalyzer:
    """Analyzes browser OPSEC failures"""
    
    def __init__(self):
        self.signals = []
    
    def check_webrtc_leak(self, vpn_ip, real_ip=None):
        """
        Check for WebRTC IP leak
        
        Args:
            vpn_ip: VPN exit IP
            real_ip: Real IP (if leaked)
        
        Returns:
            dict with leak status and attribution weight
        """
        if real_ip and real_ip != vpn_ip:
            return {
                'leaked': True,
                'vpn_ip': vpn_ip,
                'real_ip': real_ip,
                'visibility': 1.0,
                'retention': 0.9,
                'correlation': 1.0,
                'attribution_weight': 0.90,
                'risk': 'CRITICAL',
                'mitigation': 'Disable WebRTC: media.peerconnection.enabled=false'
            }
        return {'leaked': False, 'attribution_weight': 0.0}
    
    def analyze_canvas_fingerprint(self, canvas_hash):
        """
        Analyze Canvas fingerprinting uniqueness
        
        Canvas fingerprints are 99.9% unique
        """
        return {
            'canvas_hash': canvas_hash,
            'uniqueness': 0.999,
            'visibility': 1.0,
            'retention': 0.8,
            'correlation': 0.95,
            'attribution_weight': 0.76,
            'risk': 'HIGH',
            'mitigation': 'Use Tor Browser with resistFingerprinting=true'
        }
    
    def check_font_enumeration(self, fonts_list):
        """
        Check for font enumeration fingerprinting
        """
        unique_fonts = len([f for f in fonts_list if f not in ['Arial', 'Times', 'Courier']])
        
        if unique_fonts > 10:
            aw = 0.7
            risk = 'HIGH'
        elif unique_fonts > 5:
            aw = 0.5
            risk = 'MEDIUM'
        else:
            aw = 0.3
            risk = 'LOW'
        
        return {
            'total_fonts': len(fonts_list),
            'unique_fonts': unique_fonts,
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Use only system default fonts'
        }
