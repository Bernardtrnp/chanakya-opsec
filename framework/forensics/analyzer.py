"""
Forensics Attribution Analyzer
EXIF GPS, filesystem MAC times, timeline reconstruction
"""

class ForensicsAnalyzer:
    """Analyzes forensic attribution vectors"""
    
    def analyze_exif_gps(self, image_exif):
        """
        Analyze EXIF GPS data for location attribution
        
        Args:
            image_exif: dict with EXIF data
        
        Returns:
            dict with GPS analysis and attribution weight
        """
        gps_lat = image_exif.get('GPSLatitude')
        gps_lon = image_exif.get('GPSLongitude')
        
        if gps_lat and gps_lon:
            return {
                'gps_found': True,
                'latitude': gps_lat,
                'longitude': gps_lon,
                'camera_model': image_exif.get('Model', 'unknown'),
                'timestamp': image_exif.get('DateTime', 'unknown'),
                'visibility': 0.9,
                'retention': 1.0,
                'correlation': 0.9,
                'attribution_weight': 0.81,
                'risk': 'CRITICAL',
                'mitigation': 'Strip EXIF before publishing: exiftool -all= image.jpg'
            }
        return {'gps_found': False, 'attribution_weight': 0.0}
    
    def analyze_mac_times(self, file_metadata):
        """
        Analyze filesystem MAC times for timeline reconstruction
        
        MAC = Modified, Accessed, Changed
        """
        modified = file_metadata.get('modified')
        accessed = file_metadata.get('accessed')
        created = file_metadata.get('created')
        
        # Temporal clustering indicates operational window
        if modified and accessed:
            time_diff = abs((modified - accessed).total_seconds())
            
            if time_diff < 3600:  # Within 1 hour
                correlation = 0.8
                risk = 'HIGH'
            elif time_diff < 86400:  # Within 1 day
                correlation = 0.5
                risk = 'MEDIUM'
            else:
                correlation = 0.3
                risk = 'LOW'
            
            aw = 0.7 * 0.9 * correlation  # V=0.7 (requires access), R=0.9 (persistent)
            
            return {
                'modified': modified,
                'accessed': accessed,
                'created': created,
                'time_diff_seconds': time_diff,
                'attribution_weight': aw,
                'risk': risk,
                'mitigation': 'Touch files to randomize MAC times'
            }
        
        return {'attribution_weight': 0.0}
    
    def analyze_deleted_files(self, filesystem_scan):
        """
        Analyze recoverable deleted files
        """
        deleted_count = len(filesystem_scan.get('deleted_files', []))
        
        if deleted_count > 10:
            aw = 0.7
            risk = 'HIGH'
        elif deleted_count > 0:
            aw = 0.4
            risk = 'MEDIUM'
        else:
            aw = 0.0
            risk = 'LOW'
        
        return {
            'deleted_files_count': deleted_count,
            'recoverable': deleted_count > 0,
            'attribution_weight': aw,
            'risk': risk,
            'mitigation': 'Secure delete: shred -vfz -n 35 sensitive_file.txt'
        }
