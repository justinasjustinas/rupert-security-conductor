#!/bin/bash
# Local development setup script

set -e

echo "🛠️  Setting up Rupert Security Conductor development environment..."

# Create Python virtual environment
echo "📦 Creating Python virtual environment..."
python3.12 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "📚 Installing dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Create .env file template
if [ ! -f .env ]; then
  echo "📝 Creating .env file (update with your Gemini API key)..."
  cat > .env << 'EOF'
# Gemini API Configuration
GEMINI_API_KEY=your-api-key-here

# Logging
LOG_LEVEL=INFO

# GCP Configuration
GCP_PROJECT_ID=your-project-id
EOF
  echo "⚠️  Update .env file with your Gemini API key"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "📖 To start the development server:"
echo "   source venv/bin/activate"
echo "   uvicorn app.main:app --reload"
echo ""
echo "🧪 To test the API:"
echo "   curl http://localhost:8000/health"
echo "   curl -X POST http://localhost:8000/scan -H 'Content-Type: application/json' -d '{\"repository\": \"test\", \"branch\": \"main\", \"commit_hash\": \"abc123\", \"code_diff\": \"...diff content...\"}'"
