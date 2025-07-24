@echo off
echo Prowler MCP Server 실행 중...
cd /d "%~dp0" 
python src\prowler_mcp_server.py
pause
