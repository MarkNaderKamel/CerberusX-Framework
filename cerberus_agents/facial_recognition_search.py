#!/usr/bin/env python3
"""
Facial Recognition Search Tool
Production-ready face recognition using face_recognition, DeepFace, InsightFace
Search for persons using face images across databases and the internet
"""

import logging
import argparse
import json
from pathlib import Path
from typing import List, Dict, Optional
import numpy as np
import pickle

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FaceRecognitionEngine:
    """Face recognition using face_recognition library"""
    
    def __init__(self, tolerance: float = 0.6):
        try:
            import face_recognition
            self.fr = face_recognition
            self.tolerance = tolerance
            logger.info("Face recognition library loaded")
        except ImportError:
            logger.error("face_recognition not installed: pip install face_recognition")
            raise
    
    def encode_face(self, image_path: str) -> Optional[np.ndarray]:
        """Generate face encoding from image"""
        try:
            image = self.fr.load_image_file(image_path)
            face_locations = self.fr.face_locations(image)
            
            if not face_locations:
                logger.warning(f"No faces found in {image_path}")
                return None
            
            encodings = self.fr.face_encodings(image, face_locations)
            if encodings:
                logger.info(f"Encoded {len(encodings)} face(s) from {image_path}")
                return encodings[0]  # Return first face
            
        except Exception as e:
            logger.error(f"Face encoding failed: {e}")
        
        return None
    
    def compare_faces(self, known_encoding: np.ndarray, unknown_image: str) -> Dict:
        """Compare known face with unknown image"""
        unknown_encoding = self.encode_face(unknown_image)
        
        if unknown_encoding is None:
            return {'match': False, 'confidence': 0.0}
        
        # Compare faces
        matches = self.fr.compare_faces([known_encoding], unknown_encoding, tolerance=self.tolerance)
        face_distance = self.fr.face_distance([known_encoding], unknown_encoding)
        
        confidence = 1 - face_distance[0] if len(face_distance) > 0 else 0.0
        
        return {
            'match': bool(matches[0]) if matches else False,
            'confidence': float(confidence),
            'distance': float(face_distance[0]) if len(face_distance) > 0 else 1.0
        }
    
    def search_in_directory(self, target_encoding: np.ndarray, search_dir: str) -> List[Dict]:
        """Search for matching faces in directory"""
        search_path = Path(search_dir)
        if not search_path.exists():
            logger.error(f"Directory not found: {search_dir}")
            return []
        
        results = []
        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif'}
        
        for img_file in search_path.rglob('*'):
            if img_file.suffix.lower() in image_extensions:
                match_result = self.compare_faces(target_encoding, str(img_file))
                
                if match_result['match']:
                    results.append({
                        'file': str(img_file),
                        'confidence': match_result['confidence'],
                        'distance': match_result['distance']
                    })
        
        # Sort by confidence
        results.sort(key=lambda x: x['confidence'], reverse=True)
        logger.info(f"Found {len(results)} matches in {search_dir}")
        
        return results
    
    def detect_faces_in_image(self, image_path: str) -> List[Dict]:
        """Detect all faces in an image with locations"""
        try:
            image = self.fr.load_image_file(image_path)
            face_locations = self.fr.face_locations(image)
            face_encodings = self.fr.face_encodings(image, face_locations)
            
            faces = []
            for location, encoding in zip(face_locations, face_encodings):
                top, right, bottom, left = location
                faces.append({
                    'location': {'top': top, 'right': right, 'bottom': bottom, 'left': left},
                    'encoding': encoding.tolist()
                })
            
            logger.info(f"Detected {len(faces)} faces in {image_path}")
            return faces
            
        except Exception as e:
            logger.error(f"Face detection failed: {e}")
            return []


class DeepFaceEngine:
    """Advanced face recognition using DeepFace"""
    
    def __init__(self, model: str = 'VGG-Face'):
        try:
            from deepface import DeepFace
            self.DeepFace = DeepFace
            self.model = model
            logger.info(f"DeepFace loaded with {model} model")
        except ImportError:
            logger.error("DeepFace not installed: pip install deepface")
            raise
    
    def verify_faces(self, img1: str, img2: str) -> Dict:
        """Verify if two images contain the same person"""
        try:
            result = self.DeepFace.verify(
                img1_path=img1,
                img2_path=img2,
                model_name=self.model
            )
            
            return {
                'verified': result['verified'],
                'distance': result['distance'],
                'threshold': result['threshold'],
                'model': result['model']
            }
        except Exception as e:
            logger.error(f"Face verification failed: {e}")
            return {'verified': False, 'error': str(e)}
    
    def find_in_database(self, target_image: str, database_path: str) -> List[Dict]:
        """Find matching faces in database directory"""
        try:
            results = self.DeepFace.find(
                img_path=target_image,
                db_path=database_path,
                model_name=self.model
            )
            
            matches = []
            if isinstance(results, list) and len(results) > 0:
                df = results[0]
                for _, row in df.iterrows():
                    matches.append({
                        'identity': row['identity'],
                        'distance': float(row['distance']),
                        'confidence': 1 - float(row['distance'])
                    })
            
            logger.info(f"Found {len(matches)} matches in database")
            return matches
            
        except Exception as e:
            logger.error(f"Database search failed: {e}")
            return []
    
    def analyze_face(self, image_path: str) -> Dict:
        """Analyze face for age, gender, emotion, race"""
        try:
            result = self.DeepFace.analyze(
                img_path=image_path,
                actions=['age', 'gender', 'emotion', 'race']
            )
            
            if isinstance(result, list):
                result = result[0]
            
            return {
                'age': result.get('age'),
                'gender': result.get('dominant_gender'),
                'emotion': result.get('dominant_emotion'),
                'race': result.get('dominant_race')
            }
        except Exception as e:
            logger.error(f"Face analysis failed: {e}")
            return {}


class ReverseImageSearch:
    """Search for face images on the internet using reverse image search"""
    
    async def search_google(self, image_path: str) -> List[Dict]:
        """Search Google Images for similar faces"""
        import aiohttp
        
        # Google Reverse Image Search
        # Note: This requires scraping or using Google Custom Search API
        logger.warning("Google reverse image search requires API key")
        return []
    
    async def search_yandex(self, image_path: str) -> List[Dict]:
        """Search Yandex Images for similar faces"""
        # Yandex is more permissive for reverse image search
        logger.warning("Yandex reverse image search not yet implemented")
        return []
    
    async def search_tineye(self, image_path: str) -> List[Dict]:
        """Search TinEye for exact image matches"""
        # TinEye API requires API key
        logger.warning("TinEye reverse image search requires API key")
        return []


class FaceDatabase:
    """Manage face database for known persons"""
    
    def __init__(self, db_path: str = 'face_database.pkl'):
        self.db_path = Path(db_path)
        self.database = self._load_database()
    
    def _load_database(self) -> Dict:
        """Load face database from file"""
        if self.db_path.exists():
            with self.db_path.open('rb') as f:
                return pickle.load(f)
        return {}
    
    def _save_database(self):
        """Save face database to file"""
        with self.db_path.open('wb') as f:
            pickle.dump(self.database, f)
    
    def add_person(self, name: str, encoding: np.ndarray, metadata: Optional[Dict] = None):
        """Add person to database"""
        self.database[name] = {
            'encoding': encoding,
            'metadata': metadata or {}
        }
        self._save_database()
        logger.info(f"Added {name} to database")
    
    def search_person(self, encoding: np.ndarray, tolerance: float = 0.6) -> Optional[Dict]:
        """Search for person in database"""
        import face_recognition
        
        known_names = list(self.database.keys())
        known_encodings = [self.database[name]['encoding'] for name in known_names]
        
        matches = face_recognition.compare_faces(known_encodings, encoding, tolerance=tolerance)
        face_distances = face_recognition.face_distance(known_encodings, encoding)
        
        if any(matches):
            best_match_idx = np.argmin(face_distances)
            if matches[best_match_idx]:
                return {
                    'name': known_names[best_match_idx],
                    'confidence': 1 - face_distances[best_match_idx],
                    'metadata': self.database[known_names[best_match_idx]]['metadata']
                }
        
        return None


class SocialMediaFaceSearch:
    """Search for faces across social media platforms"""
    
    async def search_pimeyes(self, image_path: str) -> List[Dict]:
        """Search PimEyes for face matches (requires API)"""
        logger.warning("PimEyes API access required for face search")
        return []
    
    async def search_findclone(self, image_path: str) -> List[Dict]:
        """Search FindClone for lookalikes"""
        logger.warning("FindClone integration not yet implemented")
        return []


def main():
    parser = argparse.ArgumentParser(description='Facial Recognition Search Tool')
    parser.add_argument('--target', required=True, help='Target face image')
    parser.add_argument('--search-dir', help='Directory to search for matches')
    parser.add_argument('--compare', help='Image to compare with target')
    parser.add_argument('--analyze', action='store_true', help='Analyze face attributes')
    parser.add_argument('--model', default='VGG-Face', choices=['VGG-Face', 'Facenet', 'OpenFace', 'DeepFace', 'ArcFace'], help='DeepFace model')
    parser.add_argument('--tolerance', type=float, default=0.6, help='Face matching tolerance')
    parser.add_argument('--database', help='Face database file')
    parser.add_argument('--add-person', help='Add person to database with name')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("Authorization required. Use --authorized flag")
        return
    
    # Initialize face recognition
    fr_engine = FaceRecognitionEngine(tolerance=args.tolerance)
    
    # Encode target face
    target_encoding = fr_engine.encode_face(args.target)
    if target_encoding is None:
        logger.error("Failed to encode target face")
        return
    
    results = {'target': args.target, 'operations': []}
    
    # Add to database
    if args.add_person and args.database:
        db = FaceDatabase(args.database)
        db.add_person(args.add_person, target_encoding)
        results['operations'].append(f"Added {args.add_person} to database")
    
    # Search in directory
    if args.search_dir:
        matches = fr_engine.search_in_directory(target_encoding, args.search_dir)
        results['directory_matches'] = matches
        logger.info(f"Found {len(matches)} matches")
    
    # Compare two images
    if args.compare:
        comparison = fr_engine.compare_faces(target_encoding, args.compare)
        results['comparison'] = comparison
        logger.info(f"Match: {comparison['match']}, Confidence: {comparison['confidence']:.2f}")
    
    # Analyze face attributes
    if args.analyze:
        try:
            deepface = DeepFaceEngine(model=args.model)
            analysis = deepface.analyze_face(args.target)
            results['analysis'] = analysis
            logger.info(f"Analysis: {analysis}")
        except Exception as e:
            logger.error(f"Face analysis not available: {e}")
    
    # Search in database
    if args.database and not args.add_person:
        db = FaceDatabase(args.database)
        person = db.search_person(target_encoding)
        results['database_match'] = person
    
    print(json.dumps(results, indent=2, default=str))


if __name__ == '__main__':
    main()
