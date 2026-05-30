# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

block_cipher = None

backend_root = Path(__file__).resolve().parents[1]
app_path = backend_root / "app.py"

analysis = Analysis(
    [str(app_path)],
    pathex=[str(backend_root)],
    binaries=[],
    datas=[
        (str(backend_root / "config"), "config"),
        (str(backend_root / "templates"), "templates"),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    [],
    name="packet_peeper_backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
