#!/bin/bash
set -e

echo " ForenHive Development Stack Startup"
echo "======================================"

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. Start Docker containers
echo -e "\n${BLUE}1. Starting Docker containers...${NC}"
cd /home/pfe/forenhive
make up || true
sleep 3

# 2. Start Backend
echo -e "\n${BLUE}2. Starting FastAPI Backend (Port 8000)...${NC}"
cd /home/pfe/forenhive/backend
source venv/bin/activate
export DISABLE_AUTH=true  # Disable auth for local dev
nohup python -m uvicorn main:app --reload --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!
echo -e "${GREEN}Backend started (PID: $BACKEND_PID)${NC}"
sleep 2

# 3. Start Frontend
echo -e "\n${BLUE}3. Starting React Frontend (Port 3000)...${NC}"
cd /home/pfe/forenhive/frontend
npm start &
FRONTEND_PID=$!
echo -e "${GREEN}Frontend starting (PID: $FRONTEND_PID)${NC}"

# 4. Summary
echo -e "\n${GREEN} All services started!${NC}"
echo "======================================"
echo -e " Frontend:    ${BLUE}http://localhost:3000${NC}"
echo -e " Backend API: ${BLUE}http://localhost:8000${NC}"
echo -e " Docs:        ${BLUE}http://localhost:8000/docs${NC}"
echo "======================================"

# Keep script running
wait
