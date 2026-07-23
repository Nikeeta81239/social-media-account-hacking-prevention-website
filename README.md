# Social Media Account Hacking Prevention

This repository contains the full stack web application and AI models for detecting and preventing social media account hacking.

## Setup Instructions

Follow these steps to get the project running locally after cloning:

1. **Create and Activate a Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up the Database**
   The project uses a MySQL database. Ensure you have MySQL running. 
   - You can run the setup script to initialize the database:
     ```bash
     python setup_db.py
     ```
   *(Ensure you update any database connection strings in `backend/config.py` if your local MySQL uses a different username or password)*

4. **Run the Application**
   Navigate to the backend folder or run the Flask app from the root directory:
   ```bash
   python backend/app.py
   ```
   
5. **Access the Frontend**
   Open the HTML files in the `frontend/` directory (e.g., `frontend/login.html`) in your browser to interact with the application.
