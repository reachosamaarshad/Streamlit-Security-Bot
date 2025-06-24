#!/bin/bash

# SecureLink Chatbot Deployment Script
# This script automates the deployment to Google Cloud Run

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="securelink-chatbot"
REGION="us-central1"
PORT="8080"
MEMORY="1Gi"
CPU="1"
MAX_INSTANCES="10"

echo -e "${BLUE}🔒 SecureLink Chatbot Deployment Script${NC}"
echo "=========================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ Google Cloud SDK is not installed. Please install it first.${NC}"
    echo "Visit: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo -e "${YELLOW}⚠️  You are not authenticated with Google Cloud.${NC}"
    echo "Please run: gcloud auth login"
    exit 1
fi

# Get or set project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${YELLOW}⚠️  No project ID set.${NC}"
    read -p "Enter your Google Cloud Project ID: " PROJECT_ID
    gcloud config set project $PROJECT_ID
else
    echo -e "${GREEN}✅ Using project: $PROJECT_ID${NC}"
fi

# Confirm deployment
echo -e "${YELLOW}📋 Deployment Configuration:${NC}"
echo "  Service Name: $SERVICE_NAME"
echo "  Region: $REGION"
echo "  Port: $PORT"
echo "  Memory: $MEMORY"
echo "  CPU: $CPU"
echo "  Max Instances: $MAX_INSTANCES"
echo ""

read -p "Do you want to proceed with deployment? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}🚫 Deployment cancelled.${NC}"
    exit 0
fi

echo -e "${BLUE}🚀 Starting deployment...${NC}"

# Enable required APIs
echo -e "${YELLOW}📡 Enabling required APIs...${NC}"
gcloud services enable cloudbuild.googleapis.com --quiet
gcloud services enable run.googleapis.com --quiet
echo -e "${GREEN}✅ APIs enabled${NC}"

# Build and push the container
echo -e "${YELLOW}🔨 Building and pushing container...${NC}"
IMAGE_NAME="gcr.io/$PROJECT_ID/$SERVICE_NAME"
gcloud builds submit --tag $IMAGE_NAME --quiet
echo -e "${GREEN}✅ Container built and pushed${NC}"

# Deploy to Cloud Run
echo -e "${YELLOW}☁️  Deploying to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
    --image $IMAGE_NAME \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --port $PORT \
    --memory $MEMORY \
    --cpu $CPU \
    --max-instances $MAX_INSTANCES \
    --quiet

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format="value(status.url)")

echo -e "${GREEN}🎉 Deployment successful!${NC}"
echo ""
echo -e "${BLUE}📱 Your SecureLink Chatbot is now available at:${NC}"
echo -e "${GREEN}$SERVICE_URL${NC}"
echo ""
echo -e "${YELLOW}📊 To monitor your service:${NC}"
echo "  gcloud run services describe $SERVICE_NAME --region=$REGION"
echo ""
echo -e "${YELLOW}🔧 To update the service:${NC}"
echo "  ./deploy.sh"
echo ""
echo -e "${YELLOW}🗑️  To delete the service:${NC}"
echo "  gcloud run services delete $SERVICE_NAME --region=$REGION --quiet"
echo ""

# Optional: Open the service URL
read -p "Do you want to open the service URL in your browser? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v open &> /dev/null; then
        open $SERVICE_URL
    elif command -v xdg-open &> /dev/null; then
        xdg-open $SERVICE_URL
    else
        echo -e "${YELLOW}Please manually open: $SERVICE_URL${NC}"
    fi
fi

echo -e "${GREEN}✅ Deployment script completed!${NC}" 