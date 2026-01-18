"""
Kernel-Adjacent Syscall Pattern Analyzer

This module analyzes system call patterns for OPSEC attribution.
Lower-level signals often leak operational patterns even when higher layers are secured.

Attribution Vectors:
- Syscall sequences (unique application fingerprints)
- Timing patterns (inter-syscall delays)
- Argument patterns (file paths, network addresses)
- Frequency distributions (behavioral fingerprinting)
"""

import re
from typing import Dict, List, Tuple
from collections import Counter
import statistics


class KernelSyscallAnalyzer:
    """Analyzes syscall patterns for attribution risks"""
    
    # Common syscall sequences for different applications
    KNOWN_PATTERNS = {
        'tor': ['socket', 'connect', 'poll', 'recvfrom', 'sendto', 'close'],
        'ssh': ['socket', 'connect', 'read', 'write', 'select', 'close'],
        'vpn_openvpn': ['socket', 'bind', 'setsockopt', 'sendto', 'recvfrom'],
        'browser_firefox': ['open', 'read', 'write', 'mmap', 'munmap', 'close', 'socket'],
        'bitcoin_core': ['open', 'lseek', 'read', 'write', 'fsync', 'close'],
    }
    
    def __init__(self):
        self.syscall_log = []
        self.timing_log = []
    
    def analyze_syscall_sequence(self, syscalls: List[str]) -> Dict:
        """
        Analyze a sequence of syscalls for application fingerprinting
        
        Args:
            syscalls: List of syscall names in order
            
        Returns:
            Analysis results with pattern matches and entropy
        """
        results = {
            'total_syscalls': len(syscalls),
            'unique_syscalls': len(set(syscalls)),
            'pattern_matches': {},
            'entropy': 0.0,
            'attribution_weight': 0.0,
        }
        
        # Calculate Shannon entropy of syscall distribution
        if syscalls:
            freqs = Counter(syscalls)
            total = len(syscalls)
            entropy = -sum((count/total) * (count/total).bit_length() 
                          for count in freqs.values() if count > 0)
            results['entropy'] = entropy
        
        # Match against known application patterns
        for app, pattern in self.KNOWN_PATTERNS.items():
            # Check if pattern subsequence exists in syscalls
            if self._contains_subsequence(syscalls, pattern):
                confidence = self._calculate_pattern_confidence(syscalls, pattern)
                results['pattern_matches'][app] = confidence
        
        # Calculate attribution weight
        # High pattern match + low entropy = high attribution risk
        if results['pattern_matches']:
            max_confidence = max(results['pattern_matches'].values())
            # Low entropy means predictable behavior
            entropy_factor = 1.0 - min(results['entropy'] / 10.0, 1.0)
            results['attribution_weight'] = (max_confidence + entropy_factor) / 2
        
        return results
    
    def analyze_timing_patterns(self, syscall_times: List[Tuple[str, float]]) -> Dict:
        """
        Analyze inter-syscall timing for side-channel attribution
        
        Args:
            syscall_times: List of (syscall_name, timestamp) tuples
            
        Returns:
            Timing analysis results
        """
        if len(syscall_times) < 2:
            return {'error': 'Insufficient data'}
        
        # Calculate inter-syscall delays
        delays = []
        for i in range(1, len(syscall_times)):
            _, curr_time = syscall_times[i]
            _, prev_time = syscall_times[i-1]
            delays.append(curr_time - prev_time)
        
        results = {
            'total_samples': len(delays),
            'mean_delay_ms': statistics.mean(delays) * 1000,
            'median_delay_ms': statistics.median(delays) * 1000,
            'stddev_ms': statistics.stdev(delays) * 1000 if len(delays) > 1 else 0,
            'timing_jitter': 0.0,
            'attribution_weight': 0.0,
        }
        
        # Calculate timing jitter (coefficient of variation)
        if results['mean_delay_ms'] > 0:
            results['timing_jitter'] = results['stddev_ms'] / results['mean_delay_ms']
        
        # Low jitter = predictable timing = higher attribution
        # Jitter < 0.1 is very predictable
        if results['timing_jitter'] < 0.1:
            results['attribution_weight'] = 0.80
        elif results['timing_jitter'] < 0.5:
            results['attribution_weight'] = 0.50
        else:
            results['attribution_weight'] = 0.20
        
        # Detect periodic patterns (e.g., heartbeat, keep-alive)
        if self._detect_periodicity(delays):
            results['periodic_pattern_detected'] = True
            results['attribution_weight'] = min(results['attribution_weight'] + 0.15, 1.0)
        
        return results
    
    def analyze_file_access_patterns(self, file_paths: List[str]) -> Dict:
        """
        Analyze file access patterns for operational fingerprinting
        
        Args:
            file_paths: List of accessed file paths
            
        Returns:
            File access analysis
        """
        results = {
            'total_files': len(file_paths),
            'unique_files': len(set(file_paths)),
            'sensitive_paths_detected': [],
            'application_hints': [],
            'attribution_weight': 0.0,
        }
        
        # Detect sensitive path patterns
        sensitive_patterns = {
            'tor': [r'/\.tor/', r'/torrc$', r'/state$'],
            'vpn': [r'/\.openvpn/', r'\.ovpn$', r'/vpnc/'],
            'cryptocurrency': [r'/\.bitcoin/', r'wallet\.dat$', r'/\.monero/'],
            'encryption': [r'\.gpg$', r'/\.gnupg/', r'\.asc$'],
        }
        
        for app, patterns in sensitive_patterns.items():
            for pattern in patterns:
                matches = [path for path in file_paths if re.search(pattern, path)]
                if matches:
                    results['sensitive_paths_detected'].extend(matches)
                    results['application_hints'].append(app)
        
        # Calculate attribution weight
        if results['sensitive_paths_detected']:
            # More sensitive paths = higher attribution
            ratio = len(results['sensitive_paths_detected']) / max(len(file_paths), 1)
            results['attribution_weight'] = min(0.50 + (ratio * 0.40), 0.90)
        
        return results
    
    def detect_covert_channel(self, syscalls: List[str], threshold: int = 10) -> Dict:
        """
        Detect potential covert channel usage via syscall patterns
        
        Covert channels: Unusual syscall patterns that may indicate hidden communication
        
        Args:
            syscalls: List of syscall names
            threshold: Minimum suspicious pattern count
            
        Returns:
            Covert channel detection results
        """
        results = {
            'suspicious_patterns': [],
            'covert_channel_likely': False,
            'attribution_weight': 0.0,
        }
        
        # Detect unusual sequences
        # Example: Repeated non-network syscalls with specific timing (steganography)
        
        # Check for excessive file I/O to unusual locations
        file_syscalls = ['open', 'read', 'write', 'lseek', 'close']
        file_io_count = sum(1 for s in syscalls if s in file_syscalls)
        
        if file_io_count > len(syscalls) * 0.7:  # 70%+ file I/O
            results['suspicious_patterns'].append('Excessive file I/O (possible steganography)')
        
        # Check for unusual timing-based patterns
        # (Would need timing data for full analysis)
        
        # Check for syscalls rarely used in normal applications
        rare_syscalls = ['ptrace', 'process_vm_readv', 'process_vm_writev', 
                         'perf_event_open', 'bpf']
        rare_count = sum(1 for s in syscalls if s in rare_syscalls)
        
        if rare_count > 0:
            results['suspicious_patterns'].append(f'Rare syscalls detected: {rare_count}')
            results['attribution_weight'] = 0.70
        
        results['covert_channel_likely'] = len(results['suspicious_patterns']) >= threshold
        
        return results
    
    # Helper methods
    
    def _contains_subsequence(self, sequence: List, pattern: List) -> bool:
        """Check if pattern is a subsequence of sequence"""
        if not pattern:
            return True
        if not sequence:
            return False
        
        # Simple subsequence check
        pattern_idx = 0
        for item in sequence:
            if item == pattern[pattern_idx]:
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return True
        return False
    
    def _calculate_pattern_confidence(self, sequence: List, pattern: List) -> float:
        """Calculate confidence that sequence matches pattern"""
        if not pattern:
            return 0.0
        
        # Count how many pattern elements appear in sequence
        matches = sum(1 for p in pattern if p in sequence)
        confidence = matches / len(pattern)
        
        # Bonus for sequence match
        if self._contains_subsequence(sequence, pattern):
            confidence = min(confidence + 0.20, 1.0)
        
        return confidence
    
    def _detect_periodicity(self, delays: List[float], tolerance: float = 0.05) -> bool:
        """Detect if delays have periodic pattern"""
        if len(delays) < 10:
            return False
        
        # Simple periodicity: check if delays cluster around specific values
        mean = statistics.mean(delays)
        if mean == 0:
            return False
        
        # Check how many delays are within tolerance of mean
        within_tolerance = sum(1 for d in delays if abs(d - mean) / mean < tolerance)
        
        # If >70% of delays are periodic, consider it periodic
        return (within_tolerance / len(delays)) > 0.70


# Example usage and test
if __name__ == '__main__':
    analyzer = KernelSyscallAnalyzer()
    
    # Example 1: Tor-like syscall pattern
    print("=== Example 1: Tor-like Pattern ===")
    tor_syscalls = ['socket', 'connect', 'poll', 'recvfrom', 'sendto', 'close',
                    'socket', 'connect', 'poll', 'recvfrom', 'sendto', 'close']
    result = analyzer.analyze_syscall_sequence(tor_syscalls)
    print(f"Pattern matches: {result['pattern_matches']}")
    print(f"Attribution Weight: {result['attribution_weight']:.2f}")
    
    # Example 2: Timing analysis
    print("\n=== Example 2: Timing Analysis ===")
    syscall_times = [
        ('socket', 0.000),
        ('connect', 0.010),
        ('read', 0.020),
        ('write', 0.030),
        ('close', 0.040),
    ]
    timing_result = analyzer.analyze_timing_patterns(syscall_times)
    print(f"Mean delay: {timing_result['mean_delay_ms']:.2f} ms")
    print(f"Timing jitter: {timing_result['timing_jitter']:.3f}")
    print(f"Attribution Weight: {timing_result['attribution_weight']:.2f}")
    
    # Example 3: File access patterns
    print("\n=== Example 3: File Access Patterns ===")
    file_paths = [
        '/home/user/.tor/torrc',
        '/home/user/.bitcoin/wallet.dat',
        '/home/user/.gnupg/pubring.gpg',
        '/tmp/random123.txt',
    ]
    file_result = analyzer.analyze_file_access_patterns(file_paths)
    print(f"Sensitive paths: {file_result['sensitive_paths_detected']}")
    print(f"Application hints: {file_result['application_hints']}")
    print(f"Attribution Weight: {file_result['attribution_weight']:.2f}")
