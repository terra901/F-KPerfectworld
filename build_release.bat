@echo off
setlocal
set "ROOT=%~dp0"
set "QT_ROOT=%ROOT%toolchain\5.15.2\mingw81_64"
set "MINGW_BIN=%ROOT%toolchain\Tools\mingw810_64\bin"
set "PATH=%MINGW_BIN%;%QT_ROOT%\bin;%PATH%"

"%QT_ROOT%\bin\qmake.exe" "%ROOT%FUCKPecfectWorld.pro"
if errorlevel 1 exit /b 1

mingw32-make release
if errorlevel 1 exit /b 1

if not exist "%ROOT%bin\platforms" mkdir "%ROOT%bin\platforms"
copy /y "%QT_ROOT%\bin\Qt5Core.dll" "%ROOT%bin\" >nul
copy /y "%QT_ROOT%\bin\Qt5Gui.dll" "%ROOT%bin\" >nul
copy /y "%QT_ROOT%\bin\Qt5Network.dll" "%ROOT%bin\" >nul
copy /y "%QT_ROOT%\bin\Qt5Widgets.dll" "%ROOT%bin\" >nul
copy /y "%MINGW_BIN%\libgcc_s_seh-1.dll" "%ROOT%bin\" >nul
copy /y "%MINGW_BIN%\libstdc++-6.dll" "%ROOT%bin\" >nul
copy /y "%MINGW_BIN%\libwinpthread-1.dll" "%ROOT%bin\" >nul
copy /y "%QT_ROOT%\plugins\platforms\qwindows.dll" "%ROOT%bin\platforms\" >nul
copy /y "%ROOT%resources\default_rules.json" "%ROOT%bin\rules.json" >nul

echo Build complete: "%ROOT%bin\FUCKPecfectWorld.exe"
