# Hand Germs Detection Project

A web application that detects and analyzes germs on hands before and after cleaning, providing a cleanliness score and visual feedback.

## Features
- Upload before and after cleaning images
- Real-time germ detection and analysis
- Cleanliness score calculation
- Visual representation of detected germs
- Responsive web interface
- User authentication and history tracking

## Prerequisites
- Python 3.7 or higher
- Modern web browser
- pip (Python package installer)

## Local Installation

1. Clone or download this repository
2. Install required Python packages:
```bash
pip install -r requirements.txt
```

## Running Locally

1. Start the backend server:
```bash
python apppy.py
```
The server will start at http://127.0.0.1:5000

2. Open `index1.html` in your web browser

## Deployment to Render

### Option 1: Using Render Dashboard (Recommended)

1. **Sign up/Login to Render**
   - Go to [render.com](https://render.com)
   - Create an account or sign in

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select the repository containing this project

3. **Configure the Service**
   - **Name**: `hand-germs-detection` (or your preferred name)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn apppy:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`
   - **Plan**: Choose "Free" for testing or "Starter" for production

4. **Environment Variables** (Optional)
   - `SECRET_KEY`: Generate a secure random key
   - `FLASK_ENV`: `production`

5. **Deploy**
   - Click "Create Web Service"
   - Render will automatically build and deploy your app

### Option 2: Using render.yaml (Advanced)

1. The project includes a `render.yaml` file for automated deployment
2. Push your code to GitHub
3. In Render dashboard, choose "New +" → "Blueprint"
4. Connect your repository
5. Render will automatically configure and deploy using the yaml file

## Usage
1. Register a new account or login
2. Upload the "before cleaning" image
3. Upload the "after cleaning" image
4. Click "Process" to analyze the images
5. View the cleanliness score and visualizations
6. Check your analysis history

## Project Structure
- `apppy.py` - Backend Flask server
- `index1.html` - Frontend interface
- `styles.css` - Styling for the web interface
- `requirements.txt` - Python dependencies
- `gunicorn_config.py` - Production server configuration
- `render.yaml` - Render deployment configuration
- `uploads/` - Directory for storing uploaded images
- `germs.db` - SQLite database

## API Endpoints
- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /process` - Process images and analyze germs
- `GET /history` - Get user's analysis history
- `GET /result/<id>` - Get specific analysis result

## Contributing
Feel free to submit issues and enhancement requests!

## License
This project is licensed under the MIT License. 