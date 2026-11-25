@echo off
setlocal
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name ULCKLOADDER_V1 --icon "ulckloadder.ico" --add-data "ulckloadder.ico;." "ULCKLOADDER_V1.py"
if errorlevel 1 (
  echo.
  echo Falha ao compilar. Confira as mensagens acima.
  pause
  exit /b 1
)
echo.
echo EXE criado em: dist\ULCKLOADDER_V1.exe
pause
