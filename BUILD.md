# Build for Windows

From a virtual environment with the requirements installed, run:

```powershell
py -m pip install pyinstaller
pyinstaller --onefile --windowed --name PasswordVault main.py
```

The executable will be created at `dist\PasswordVault.exe`. PyInstaller packages the Python runtime and the listed crypto dependencies; build on Windows for a Windows executable.
