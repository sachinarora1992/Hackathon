## This is the main file used to install dependencies for the project
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
uv add fastapi mcp[cli] httpx 