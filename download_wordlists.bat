@echo off
title RockYou 2025 Wordlist Downloader
color 0B

echo =====================================================
echo   RockYou 2025 Wordlist Downloader
echo   Password Checker uchun so'zlik yuklash
echo =====================================================
echo.
echo Jami yuklab olinadi: ~150 MB (6 fayl x 25 MB)
echo Fayllar: wordlists\ papkasiga saqlanadi
echo.
echo Davom etish uchun istalgan tugmani bosing...
echo Bekor qilish uchun Ctrl+C bosing.
pause >nul

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [XATO] Python topilmadi. Avval Python o'rnating.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
python download_wordlists.py
echo.
pause
