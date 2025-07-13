# Render Deployment Guide for Hand Germs Detection

## Prerequisites
- GitHub account
- Render account (free at [render.com](https://render.com))
- Your project code pushed to GitHub

## Step-by-Step Deployment

### Step 1: Prepare Your Repository
1. Make sure all your project files are in the `Germs` folder
2. Push your code to GitHub if you haven't already
3. Ensure the following files are present:
   - `apppy.py`
   - `requirements.txt`
   - `index1.html`
   - `styles.css`
   - `gunicorn_config.py` (created for deployment)
   - `render.yaml` (created for deployment)

### Step 2: Sign Up for Render
1. Go to [render.com](https://render.com)
2. Click "Get Started for Free"
3. Sign up with your GitHub account (recommended) or email

### Step 3: Create Web Service
1. In your Render dashboard, click "New +"
2. Select "Web Service"
3. Connect your GitHub repository
4. Select the repository containing your project

### Step 4: Configure the Service
Fill in the following details:

**Basic Settings:**
- **Name**: `hand-germs-detection` (or your preferred name)
- **Environment**: `Python 3`
- **Region**: Choose closest to your users
- **Branch**: `main` (or your default branch)

**Build & Deploy Settings:**
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn apppy:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`

**Plan:**
- **Free**: For testing and development (limited resources)
- **Starter**: For production use ($7/month, better performance)

### Step 5: Environment Variables (Optional)
Add these environment variables in the "Environment" tab:

| Key | Value | Description |
|-----|-------|-------------|
| `SECRET_KEY` | `your-secret-key-here` | Generate a secure random string |
| `FLASK_ENV` | `production` | Set Flask environment |
| `PYTHON_VERSION` | `3.9.18` | Python version |

### Step 6: Deploy
1. Click "Create Web Service"
2. Render will automatically:
   - Clone your repository
   - Install dependencies
   - Build your application
   - Deploy it to a live URL

### Step 7: Access Your Application
1. Wait for the build to complete (usually 2-5 minutes)
2. Your app will be available at: `https://your-app-name.onrender.com`
3. Click the URL to test your application

## Troubleshooting

### Common Issues:

**1. Build Fails**
- Check that `requirements.txt` is in the root directory
- Ensure all dependencies are listed correctly
- Check the build logs for specific errors

**2. Application Won't Start**
- Verify the start command is correct
- Check that `apppy.py` contains the Flask app
- Review the logs for startup errors

**3. Database Issues**
- SQLite files are ephemeral on Render (they reset on each deploy)
- Consider using a persistent database for production

**4. File Upload Issues**
- Ensure the `uploads` directory exists
- Check file permissions
- Verify file size limits

### Useful Commands:
- **View Logs**: Go to your service → "Logs" tab
- **Manual Deploy**: Go to your service → "Manual Deploy"
- **Environment Variables**: Go to your service → "Environment" tab

## Free Tier Limitations
- **Sleep after 15 minutes** of inactivity
- **512 MB RAM** limit
- **Shared CPU** resources
- **750 hours/month** of runtime

## Upgrading to Paid Plan
If you need better performance:
1. Go to your service settings
2. Click "Change Plan"
3. Select "Starter" ($7/month)
4. Benefits:
   - Always-on (no sleep)
   - 512 MB RAM
   - Dedicated CPU
   - Custom domains

## Monitoring Your App
- **Health Checks**: Render automatically monitors your app
- **Logs**: Real-time logs available in dashboard
- **Metrics**: Basic performance metrics included

## Next Steps
1. Test all functionality on the deployed app
2. Set up a custom domain (optional)
3. Configure SSL certificates (automatic on Render)
4. Set up monitoring and alerts
5. Consider database migration for production use

## Support
- **Render Documentation**: [docs.render.com](https://docs.render.com)
- **Render Community**: [community.render.com](https://community.render.com)
- **GitHub Issues**: For project-specific issues 