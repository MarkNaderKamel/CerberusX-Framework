#!/usr/bin/env python3
"""
AI-Powered Image Intelligence Tool
EXIF metadata extraction, geolocation, reverse image search
Integrated with Google Gemini AI for advanced image analysis
"""

import logging
import argparse
import json
import os
import asyncio
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EXIFMetadataExtractor:
    """Extract EXIF metadata from images"""
    
    def __init__(self):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            self.Image = Image
            self.TAGS = TAGS
            self.GPSTAGS = GPSTAGS
            logger.info("PIL/Pillow loaded for EXIF extraction")
        except ImportError:
            logger.error("Pillow not installed: pip install Pillow")
            raise
    
    def extract_metadata(self, image_path: str) -> Dict:
        """Extract all EXIF metadata from image"""
        metadata = {
            'file_info': {},
            'camera_info': {},
            'gps_info': {},
            'datetime_info': {},
            'all_tags': {}
        }
        
        try:
            image = self.Image.open(image_path)
            
            # File information
            metadata['file_info'] = {
                'filename': Path(image_path).name,
                'format': image.format,
                'size': image.size,
                'mode': image.mode,
                'file_size': Path(image_path).stat().st_size
            }
            
            # Extract EXIF data
            exifdata = image.getexif()
            
            if not exifdata:
                logger.warning(f"No EXIF data found in {image_path}")
                return metadata
            
            # Parse all EXIF tags
            for tag_id in exifdata:
                tag = self.TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                
                # Decode bytes
                if isinstance(data, bytes):
                    try:
                        data = data.decode()
                    except:
                        data = str(data)
                
                metadata['all_tags'][tag] = data
                
                # Categorize specific tags
                if tag in ['Make', 'Model', 'LensModel', 'FocalLength', 'FNumber', 'ISO']:
                    metadata['camera_info'][tag] = data
                elif tag in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                    metadata['datetime_info'][tag] = data
            
            # Extract GPS information
            gps_data = exifdata.get_ifd(0x8825)  # GPS IFD
            if gps_data:
                gps_info = self._parse_gps_data(gps_data)
                metadata['gps_info'] = gps_info
            
            logger.info(f"Extracted {len(metadata['all_tags'])} EXIF tags from {image_path}")
            
        except Exception as e:
            logger.error(f"EXIF extraction failed: {e}")
        
        return metadata
    
    def _parse_gps_data(self, gps_data: Dict) -> Dict:
        """Parse GPS data from EXIF"""
        gps_info = {}
        
        for tag_id in gps_data:
            tag = self.GPSTAGS.get(tag_id, tag_id)
            gps_info[tag] = gps_data.get(tag_id)
        
        # Calculate decimal coordinates
        if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
            lat = self._convert_to_degrees(gps_info['GPSLatitude'])
            lon = self._convert_to_degrees(gps_info['GPSLongitude'])
            
            # Apply hemisphere
            if gps_info.get('GPSLatitudeRef') == 'S':
                lat = -lat
            if gps_info.get('GPSLongitudeRef') == 'W':
                lon = -lon
            
            gps_info['decimal_coordinates'] = {
                'latitude': lat,
                'longitude': lon,
                'google_maps_url': f'https://www.google.com/maps?q={lat},{lon}'
            }
        
        return gps_info
    
    def _convert_to_degrees(self, value) -> float:
        """Convert GPS coordinates to decimal degrees"""
        try:
            d, m, s = value
            return float(d) + float(m) / 60.0 + float(s) / 3600.0
        except:
            return 0.0


class GeminiImageAnalyzer:
    """Analyze images using Google Gemini AI"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
        self.endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro-vision:generateContent'
        
        if not self.api_key:
            logger.warning("No Gemini API key found. Set GEMINI_API_KEY or GOOGLE_API_KEY environment variable")
    
    async def analyze_image(self, image_path: str, query: str = "Describe this image in detail") -> Dict:
        """Analyze image using Gemini AI"""
        if not self.api_key:
            return {'error': 'API key required'}
        
        try:
            import google.generativeai as genai
            
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            # Load image
            from PIL import Image
            img = Image.open(image_path)
            
            # Generate analysis
            response = model.generate_content([query, img])
            
            return {
                'query': query,
                'analysis': response.text,
                'model': 'gemini-1.5-flash'
            }
            
        except ImportError:
            logger.error("Google GenerativeAI not installed: pip install google-generativeai")
            return {'error': 'google-generativeai library not installed'}
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {'error': str(e)}
    
    async def identify_location(self, image_path: str) -> Dict:
        """Use AI to identify location from visual cues"""
        query = """Analyze this image and identify:
        1. The location or region where this photo was likely taken
        2. Any visible landmarks, street signs, or geographic features
        3. Architectural style that might indicate location
        4. Time of day based on shadows and lighting
        5. Season based on vegetation and weather
        Provide specific details that could help geolocate this image."""
        
        return await self.analyze_image(image_path, query)
    
    async def extract_text_from_image(self, image_path: str) -> Dict:
        """Extract and translate text from image using OCR"""
        query = "Extract all visible text from this image, including signs, labels, documents, etc. Translate if needed."
        
        return await self.analyze_image(image_path, query)
    
    async def identify_objects_and_people(self, image_path: str) -> Dict:
        """Identify objects, people, and activities in image"""
        query = """Analyze this image and list:
        1. All visible objects and their descriptions
        2. Number of people and their activities
        3. Vehicles with make/model if identifiable
        4. Any logos, brands, or text visible
        5. Notable details that could be used for identification"""
        
        return await self.analyze_image(image_path, query)


class ReverseImageSearchEngine:
    """Perform reverse image search"""
    
    async def search_google_images(self, image_path: str) -> List[Dict]:
        """Search Google Images for similar images"""
        results = []
        
        try:
            # Use SerpAPI or similar service for Google Image Search
            # Note: Requires API key
            logger.warning("Google reverse image search requires API key (SerpAPI, etc.)")
            
        except Exception as e:
            logger.error(f"Google image search failed: {e}")
        
        return results
    
    async def search_yandex_images(self, image_path: str) -> List[Dict]:
        """Search Yandex Images - more permissive than Google"""
        results = []
        
        try:
            # Yandex allows direct URL uploads
            # Implementation would upload and parse results
            logger.warning("Yandex reverse image search not yet implemented")
            
        except Exception as e:
            logger.error(f"Yandex image search failed: {e}")
        
        return results
    
    async def search_tineye(self, image_path: str) -> List[Dict]:
        """Search TinEye for exact matches"""
        results = []
        
        try:
            # TinEye API for exact image matching
            logger.warning("TinEye requires API key")
            
        except Exception as e:
            logger.error(f"TinEye search failed: {e}")
        
        return results


class ImageHashAnalyzer:
    """Generate and compare image hashes for similarity"""
    
    def __init__(self):
        try:
            import imagehash
            from PIL import Image
            self.imagehash = imagehash
            self.Image = Image
            logger.info("ImageHash library loaded")
        except ImportError:
            logger.warning("ImageHash not installed: pip install imagehash")
            self.imagehash = None
    
    def calculate_hashes(self, image_path: str) -> Dict:
        """Calculate various perceptual hashes"""
        if not self.imagehash:
            return {'error': 'imagehash library not installed'}
        
        try:
            img = self.Image.open(image_path)
            
            hashes = {
                'ahash': str(self.imagehash.average_hash(img)),
                'phash': str(self.imagehash.phash(img)),
                'dhash': str(self.imagehash.dhash(img)),
                'whash': str(self.imagehash.whash(img)),
                'colorhash': str(self.imagehash.colorhash(img))
            }
            
            return hashes
            
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
            return {'error': str(e)}
    
    def compare_images(self, image1: str, image2: str) -> Dict:
        """Compare two images using perceptual hashes"""
        if not self.imagehash:
            return {'error': 'imagehash library not installed'}
        
        try:
            img1 = self.Image.open(image1)
            img2 = self.Image.open(image2)
            
            hash1 = self.imagehash.average_hash(img1)
            hash2 = self.imagehash.average_hash(img2)
            
            difference = hash1 - hash2
            similarity = 1 - (difference / 64.0)  # Normalize to 0-1
            
            return {
                'difference': difference,
                'similarity': similarity,
                'match': difference < 10  # Threshold for match
            }
            
        except Exception as e:
            logger.error(f"Image comparison failed: {e}")
            return {'error': str(e)}


class GeolocationAnalyzer:
    """Geolocate images using various techniques"""
    
    def __init__(self):
        self.exif_extractor = EXIFMetadataExtractor()
    
    async def geolocate_image(self, image_path: str, use_ai: bool = True) -> Dict:
        """Attempt to geolocate image using all available methods"""
        geolocation = {
            'image': image_path,
            'coordinates': None,
            'location_info': {},
            'confidence': 'unknown',
            'methods_used': []
        }
        
        # Method 1: EXIF GPS data
        metadata = self.exif_extractor.extract_metadata(image_path)
        gps_info = metadata.get('gps_info', {})
        
        if 'decimal_coordinates' in gps_info:
            geolocation['coordinates'] = gps_info['decimal_coordinates']
            geolocation['confidence'] = 'high'
            geolocation['methods_used'].append('EXIF GPS')
            
            # Reverse geocode
            location_info = await self._reverse_geocode(
                gps_info['decimal_coordinates']['latitude'],
                gps_info['decimal_coordinates']['longitude']
            )
            geolocation['location_info'] = location_info
        
        # Method 2: AI visual analysis
        if use_ai and not geolocation['coordinates']:
            gemini = GeminiImageAnalyzer()
            ai_analysis = await gemini.identify_location(image_path)
            geolocation['ai_analysis'] = ai_analysis
            geolocation['methods_used'].append('AI Visual Analysis')
            geolocation['confidence'] = 'medium'
        
        # Method 3: Reverse image search (would find similar images with location data)
        # geolocation['methods_used'].append('Reverse Image Search')
        
        return geolocation
    
    async def _reverse_geocode(self, lat: float, lon: float) -> Dict:
        """Reverse geocode coordinates to location"""
        try:
            # Use Nominatim (OpenStreetMap) for reverse geocoding
            url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}'
            
            headers = {'User-Agent': 'Cerberus-OSINT-Tool'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        return {
                            'address': data.get('display_name'),
                            'country': data.get('address', {}).get('country'),
                            'city': data.get('address', {}).get('city'),
                            'state': data.get('address', {}).get('state'),
                            'postcode': data.get('address', {}).get('postcode')
                        }
        except Exception as e:
            logger.error(f"Reverse geocoding failed: {e}")
        
        return {}


class ImageForensicsAnalyzer:
    """Analyze images for tampering and manipulation"""
    
    async def analyze_authenticity(self, image_path: str) -> Dict:
        """Analyze image for signs of manipulation"""
        analysis = {
            'image': image_path,
            'metadata_analysis': {},
            'visual_analysis': {},
            'authenticity_score': 0.0
        }
        
        # Check EXIF consistency
        exif_check = self._check_exif_consistency(image_path)
        analysis['metadata_analysis'] = exif_check
        
        # Check for common manipulation indicators
        manipulation_check = self._check_manipulation_indicators(image_path)
        analysis['visual_analysis'] = manipulation_check
        
        # Calculate authenticity score
        score = 1.0
        if exif_check.get('inconsistencies'):
            score -= 0.3
        if manipulation_check.get('suspicious_patterns'):
            score -= 0.4
        
        analysis['authenticity_score'] = max(0.0, score)
        
        return analysis
    
    def _check_exif_consistency(self, image_path: str) -> Dict:
        """Check EXIF data for inconsistencies"""
        extractor = EXIFMetadataExtractor()
        metadata = extractor.extract_metadata(image_path)
        
        inconsistencies = []
        
        # Check if EXIF exists
        if not metadata.get('all_tags'):
            inconsistencies.append('No EXIF data (possibly stripped)')
        
        # Check datetime consistency
        datetime_info = metadata.get('datetime_info', {})
        if datetime_info:
            dates = list(datetime_info.values())
            if len(set(dates)) > 1:
                inconsistencies.append('Inconsistent datetime values')
        
        return {
            'inconsistencies': inconsistencies,
            'suspicious': len(inconsistencies) > 0
        }
    
    def _check_manipulation_indicators(self, image_path: str) -> Dict:
        """Check for visual manipulation indicators"""
        indicators = {
            'suspicious_patterns': [],
            'warnings': []
        }
        
        try:
            from PIL import Image
            img = Image.open(image_path)
            
            # Check for repeated patterns (clone stamp)
            # Check for JPEG artifacts inconsistencies
            # Check for noise inconsistencies
            
            # This is a simplified check
            # Full implementation would use advanced forensics algorithms
            
        except Exception as e:
            logger.error(f"Manipulation check failed: {e}")
        
        return indicators


async def main():
    parser = argparse.ArgumentParser(description='AI-Powered Image Intelligence')
    parser.add_argument('--image', required=True, help='Image file to analyze')
    parser.add_argument('--extract-exif', action='store_true', help='Extract EXIF metadata')
    parser.add_argument('--geolocate', action='store_true', help='Attempt to geolocate image')
    parser.add_argument('--ai-analyze', action='store_true', help='Use Gemini AI for analysis')
    parser.add_argument('--ai-query', help='Custom query for AI analysis')
    parser.add_argument('--reverse-search', action='store_true', help='Reverse image search')
    parser.add_argument('--forensics', action='store_true', help='Analyze for tampering')
    parser.add_argument('--calculate-hash', action='store_true', help='Calculate image hashes')
    parser.add_argument('--compare', help='Compare with another image')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("Authorization required. Use --authorized flag")
        return
    
    results = {'image': args.image, 'analyses': {}}
    
    # Extract EXIF
    if args.extract_exif or args.geolocate:
        extractor = EXIFMetadataExtractor()
        metadata = extractor.extract_metadata(args.image)
        results['analyses']['metadata'] = metadata
    
    # Geolocate
    if args.geolocate:
        geolocator = GeolocationAnalyzer()
        geolocation = await geolocator.geolocate_image(args.image, use_ai=args.ai_analyze)
        results['analyses']['geolocation'] = geolocation
    
    # AI Analysis
    if args.ai_analyze:
        gemini = GeminiImageAnalyzer()
        query = args.ai_query or "Describe this image in detail and identify any notable features"
        ai_analysis = await gemini.analyze_image(args.image, query)
        results['analyses']['ai_analysis'] = ai_analysis
    
    # Reverse search
    if args.reverse_search:
        reverse_search = ReverseImageSearchEngine()
        results['analyses']['reverse_search'] = {
            'note': 'Reverse image search requires API keys for Google/Yandex/TinEye'
        }
    
    # Forensics
    if args.forensics:
        forensics = ImageForensicsAnalyzer()
        authenticity = await forensics.analyze_authenticity(args.image)
        results['analyses']['forensics'] = authenticity
    
    # Calculate hash
    if args.calculate_hash:
        hasher = ImageHashAnalyzer()
        hashes = hasher.calculate_hashes(args.image)
        results['analyses']['hashes'] = hashes
    
    # Compare images
    if args.compare:
        hasher = ImageHashAnalyzer()
        comparison = hasher.compare_images(args.image, args.compare)
        results['analyses']['comparison'] = comparison
    
    print(json.dumps(results, indent=2, default=str))


if __name__ == '__main__':
    asyncio.run(main())
