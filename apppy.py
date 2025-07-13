import base64
import cv2
import numpy as np
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import os
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import uuid
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Update CORS configuration to allow all origins
CORS(app, resources={
    r"/*": {
        "origins": "*",  # Allow all origins during development
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', str(uuid.uuid4()))

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
UPLOAD_FOLDER = 'uploads'

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup
Base = declarative_base()
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'germs.db')
engine = create_engine(f'sqlite:///{db_path}', echo=True)
Session = sessionmaker(bind=engine)

# Initialize database
def init_db():
    try:
        Base.metadata.create_all(engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

# Initialize database on startup
init_db()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128))
    created_at = Column(DateTime, default=datetime.utcnow)
    results = relationship('Result', back_populates='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Result(Base):
    __tablename__ = 'results'
    id = Column(Integer, primary_key=True)
    cleanliness_score = Column(Float)
    before_image = Column(String)
    after_image = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User', back_populates='results')

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format', 'code': 'AUTH_ERROR'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing', 'code': 'AUTH_ERROR'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            session = Session()
            current_user = session.query(User).get(data['user_id'])
            session.close()
            
            if not current_user:
                return jsonify({'error': 'Invalid token', 'code': 'AUTH_ERROR'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired', 'code': 'AUTH_ERROR'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token', 'code': 'AUTH_ERROR'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({'error': 'Token validation failed', 'code': 'AUTH_ERROR'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Authentication routes
@app.route('/register', methods=['POST'])
def register():
    session = None
    try:
        data = request.get_json()
        logger.info(f"Registration attempt for username: {data.get('username')}")
        
        if not all(k in data for k in ['username', 'email', 'password']):
            return jsonify({'error': 'Missing required fields', 'code': 'VALIDATION_ERROR'}), 400

        session = Session()
        
        # Check if username or email already exists
        if session.query(User).filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists', 'code': 'VALIDATION_ERROR'}), 400
        if session.query(User).filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists', 'code': 'VALIDATION_ERROR'}), 400

        # Create new user
        user = User(username=data['username'], email=data['email'])
        user.set_password(data['password'])
        
        session.add(user)
        session.commit()
        
        # Generate token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(days=1)
        }, app.config['SECRET_KEY'])
        
        logger.info(f"User registered successfully: {user.username}")
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 201

    except Exception as e:
        if session:
            session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': str(e), 'code': 'UNKNOWN_ERROR'}), 500
    finally:
        if session:
            session.close()

@app.route('/login', methods=['POST'])
def login():
    session = None
    try:
        data = request.get_json()
        logger.info(f"Login attempt for username: {data.get('username')}")
        
        if not all(k in data for k in ['username', 'password']):
            return jsonify({'error': 'Missing required fields', 'code': 'VALIDATION_ERROR'}), 400

        session = Session()
        user = session.query(User).filter_by(username=data['username']).first()
        
        if user and user.check_password(data['password']):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['SECRET_KEY'])
            
            logger.info(f"User logged in successfully: {user.username}")
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
        
        logger.warning(f"Failed login attempt for username: {data.get('username')}")
        return jsonify({'error': 'Invalid username or password', 'code': 'AUTH_ERROR'}), 401

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e), 'code': 'UNKNOWN_ERROR'}), 500
    finally:
        if session:
            session.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image_file(file):
    if not file:
        raise ValueError("No file uploaded")
    
    if not file.filename:
        raise ValueError("Invalid filename")
    
    if not allowed_file(file.filename):
        raise ValueError(f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}")
    
    if len(file.read()) > MAX_FILE_SIZE:
        raise ValueError(f"File size exceeds maximum limit of {MAX_FILE_SIZE/1024/1024}MB")
    
    # Reset file pointer after reading
    file.seek(0)
    return True

def validate_image_content(image):
    if image is None:
        raise ValueError("Invalid image data")
    
    if image.size == 0:
        raise ValueError("Empty image")
    
    # Check image dimensions
    height, width = image.shape[:2]
    if width < 100 or height < 100:
        raise ValueError("Image dimensions too small")
    if width > 4000 or height > 4000:
        raise ValueError("Image dimensions too large")
    
    return True

def preprocess_image(image):
    try:
        if image is None:
            raise ValueError("Invalid image data")
        
        if len(image.shape) != 3:
            raise ValueError("Image must be in color format")
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply Gaussian blur to reduce noise
        blur = cv2.GaussianBlur(gray, (5, 5), 0)
        
        # Apply adaptive thresholding
        thresh = cv2.adaptiveThreshold(blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                     cv2.THRESH_BINARY_INV, 11, 2)
        
        return thresh
    except Exception as e:
        logger.error(f"Error in preprocess_image: {str(e)}")
        raise ValueError(f"Error preprocessing image: {str(e)}")

def detect_germs(image):
    try:
        # Find contours
        contours, _ = cv2.findContours(image, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # Filter contours by area
        min_contour_area = 50  # Minimum area to be considered a germ
        filtered_contours = [c for c in contours if cv2.contourArea(c) > min_contour_area]
        
        # Calculate total germ area
        germ_area = sum(cv2.contourArea(c) for c in filtered_contours)
        
        return germ_area, filtered_contours
    except Exception as e:
        logger.error(f"Error in detect_germs: {str(e)}")
        raise ValueError(f"Error detecting germs: {str(e)}")

def visualize_germs(image, contours):
    try:
        # Create a copy of the original image
        output = image.copy()
        
        # Draw contours in green
        cv2.drawContours(output, contours, -1, (0, 255, 0), 2)
        
        # Add text showing number of germs detected
        num_germs = len(contours)
        cv2.putText(output, f'Germs: {num_germs}', (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        
        return output
    except Exception as e:
        logger.error(f"Error in visualize_germs: {str(e)}")
        raise ValueError(f"Error visualizing germs: {str(e)}")

def calculate_cleanliness(before_area, after_area):
    try:
        if before_area == 0:
            return 100.0
        
        # Calculate the percentage of germs removed
        removal_ratio = (before_area - after_area) / before_area
        cleanliness_score = max(0, min(removal_ratio * 100, 100))
        
        return round(cleanliness_score, 2)
    except Exception as e:
        logger.error(f"Error in calculate_cleanliness: {str(e)}")
        raise ValueError(f"Error calculating cleanliness: {str(e)}")

def encode_image(image):
    try:
        # Convert image to PNG format
        _, buffer = cv2.imencode('.png', image)
        # Encode to base64
        return base64.b64encode(buffer).decode('utf-8')
    except Exception as e:
        logger.error(f"Error in encode_image: {str(e)}")
        raise ValueError(f"Error encoding image: {str(e)}")

@app.route('/process', methods=['POST'])
@token_required
def process_images(current_user):
    try:
        logger.info("Processing images request received")
        
        # Check if files are present in request
        if 'before' not in request.files or 'after' not in request.files:
            return jsonify({
                "error": "Both before and after images are required",
                "code": "MISSING_FILES"
            }), 400

        before_file = request.files['before']
        after_file = request.files['after']

        # Validate file types and sizes
        try:
            validate_image_file(before_file)
            validate_image_file(after_file)
        except ValueError as e:
            logger.error(f"File validation error: {str(e)}")
            return jsonify({
                "error": str(e),
                "code": "VALIDATION_ERROR"
            }), 400

        # Process images
        try:
            # Read images
            before_bytes = before_file.read()
            after_bytes = after_file.read()
            
            # Convert to numpy arrays
            before_image = cv2.imdecode(np.frombuffer(before_bytes, np.uint8), cv2.IMREAD_COLOR)
            after_image = cv2.imdecode(np.frombuffer(after_bytes, np.uint8), cv2.IMREAD_COLOR)
            
            if before_image is None or after_image is None:
                raise ValueError("Failed to decode images")
                
        except Exception as e:
            logger.error(f"Image processing error: {str(e)}")
            return jsonify({
                "error": "Error processing image data",
                "code": "PROCESSING_ERROR"
            }), 400

        # Validate image content
        try:
            validate_image_content(before_image)
            validate_image_content(after_image)
        except ValueError as e:
            logger.error(f"Image content validation error: {str(e)}")
            return jsonify({
                "error": str(e),
                "code": "CONTENT_ERROR"
            }), 400

        # Process images
        try:
            # Preprocess images
            preprocessed_before = preprocess_image(before_image)
            preprocessed_after = preprocess_image(after_image)
            
            # Detect germs
            before_area, before_contours = detect_germs(preprocessed_before)
            after_area, after_contours = detect_germs(preprocessed_after)
            
            logger.info(f"Germ areas - Before: {before_area}, After: {after_area}")
            
        except ValueError as e:
            logger.error(f"Analysis error: {str(e)}")
            return jsonify({
                "error": str(e),
                "code": "ANALYSIS_ERROR"
            }), 400

        # Visualize results
        try:
            before_visualization = visualize_germs(before_image, before_contours)
            after_visualization = visualize_germs(after_image, after_contours)
        except ValueError as e:
            logger.error(f"Visualization error: {str(e)}")
            return jsonify({
                "error": str(e),
                "code": "VISUALIZATION_ERROR"
            }), 400

        # Calculate score
        try:
            cleanliness_score = calculate_cleanliness(before_area, after_area)
            logger.info(f"Cleanliness score: {cleanliness_score}")
        except ValueError as e:
            logger.error(f"Score calculation error: {str(e)}")
            return jsonify({
                "error": str(e),
                "code": "SCORE_ERROR"
            }), 400

        # Save to database
        try:
            session = Session()
            result = Result(
                cleanliness_score=cleanliness_score,
                before_image=encode_image(before_visualization),
                after_image=encode_image(after_visualization),
                user_id=current_user.id
            )
            session.add(result)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return jsonify({
                "error": "Error saving results",
                "code": "DATABASE_ERROR"
            }), 500

        # Prepare response
        response_data = {
            "cleanliness_score": cleanliness_score,
            "before_visualization": encode_image(before_visualization),
            "after_visualization": encode_image(after_visualization),
            "result_id": result.id,
            "germs_detected": {
                "before": len(before_contours),
                "after": len(after_contours)
            }
        }

        logger.info("Image processing completed successfully")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "error": f"An unexpected error occurred: {str(e)}",
            "code": "UNKNOWN_ERROR"
        }), 500

@app.route('/history', methods=['GET'])
@token_required
def get_history(current_user):
    try:
        session = Session()
        results = session.query(Result).filter_by(user_id=current_user.id).order_by(Result.timestamp.desc()).limit(10).all()
        session.close()

        history = [{
            "id": r.id,
            "cleanliness_score": r.cleanliness_score,
            "timestamp": r.timestamp.isoformat(),
            "before_image": r.before_image,
            "after_image": r.after_image
        } for r in results]

        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/result/<int:result_id>', methods=['GET'])
@token_required
def get_result(current_user, result_id):
    try:
        session = Session()
        result = session.query(Result).filter_by(id=result_id, user_id=current_user.id).first()
        session.close()

        if not result:
            return jsonify({"error": "Result not found"}), 404

        return jsonify({
            "id": result.id,
            "cleanliness_score": result.cleanliness_score,
            "timestamp": result.timestamp.isoformat(),
            "before_image": result.before_image,
            "after_image": result.after_image
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
