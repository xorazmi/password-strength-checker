@echo off
title Password Checker - Windows EXE Builder
color 0A

echo ============================================
echo   Password Checker - EXE Builder
echo   Windows uchun avtomatik o'rnatish
echo ============================================
echo.

:: Python bor-yo'qligini tekshirish
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python topilmadi.
    echo [!] Iltimos python.org dan Python yuklab o'rnating:
    echo     https://www.python.org/downloads/
    echo.
    echo [!] O'rnatayotganda "Add Python to PATH" katagini belgilang!
    echo.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python topildi:
python --version
echo.

:: pip yangilash
echo [*] pip yangilanmoqda...
python -m pip install --upgrade pip --quiet

:: PyInstaller o'rnatish
echo [*] PyInstaller o'rnatilmoqda...
python -m pip install pyinstaller --quiet
if %errorlevel% neq 0 (
    echo [XATO] PyInstaller o'rnatishda muammo yuz berdi.
    pause
    exit /b 1
)
echo [OK] PyInstaller tayyor.
echo.

echo Qaysi versiyani yaratmoqchisiz?
echo.
echo   [1] GUI (grafik oyna - tavsiya etiladi)
echo   [2] Terminal (cmd oynasida ishlaydi)
echo.
set /p choice="Tanlang (1 yoki 2): "

if "%choice%"=="2" goto terminal
goto gui

:gui
echo.
echo [*] GUI versiya (password-checker-gui.exe) yasalmoqda...
python -m PyInstaller --onefile --windowed --name password-checker-gui --add-data "wordlist.txt;." gui.py --noconfirm
if %errorlevel% neq 0 ( echo [XATO] Yaratishda muammo. & pause & exit /b 1 )
echo [OK] dist\password-checker-gui.exe tayyor!
goto done

:terminal
echo.
echo [*] Terminal versiya (password-checker.exe) yasalmoqda...
python -m PyInstaller --onefile --name password-checker --add-data "wordlist.txt;." main.py --noconfirm
if %errorlevel% neq 0 ( echo [XATO] Yaratishda muammo. & pause & exit /b 1 )
echo [OK] dist\password-checker.exe tayyor!
goto done

:done
echo.
echo ============================================
echo   [TAYYOR] EXE yasaldi! Joyi: dist\ papkasi
echo ============================================
echo.
explorer dist
pause
