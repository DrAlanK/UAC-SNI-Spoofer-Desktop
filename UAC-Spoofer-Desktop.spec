# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files

datas = [
    ('assets', 'assets'),

    ('bin/xray.exe', 'bin'),
    ('bin/geoip.dat', 'bin'),
    ('bin/geosite.dat', 'bin'),

    ('bin/sing-box.exe', 'bin'),
    ('bin/libcronet.dll', 'bin'),
    ('bin/sing-box-LICENSE', 'bin'),

    # ---- Tor Expert Bundle + pluggable transports ----
    ('bin/tor/tor.exe', 'bin/tor'),
    ('bin/tor/tor-gencert.exe', 'bin/tor'),
    ('bin/tor/geoip', 'bin/tor'),
    ('bin/tor/geoip6', 'bin/tor'),   
    ('bin/tor/pluggable_transports/lyrebird.exe',
     'bin/tor/pluggable_transports'),
    ('bin/tor/pluggable_transports/conjure-client.exe',
     'bin/tor/pluggable_transports'),
    ('bin/tor/pluggable_transports/pt_config.json',
     'bin/tor/pluggable_transports'),

    ('wizard guider', 'wizard guider'),
    (
        'third_party/patterniha_sni_spoofing',
        'third_party/patterniha_sni_spoofing',
    ),
]
datas += collect_data_files('pydivert.windivert_dll')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'stem',
        'stem.control',
        'stem.connection',
        'stem.socket',
        'socks',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'kivy', 'kivymd', 'pygame', 'arcade', 'playwright',
        'numpy', 'matplotlib', 'IPython', 'pytest', 'PIL', 'cryptography',
        'bcrypt', 'pygments', 'jedi',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='UAC-Spoofer-Desktop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='assets/icon.png',
    uac_admin=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='UAC-Spoofer-Desktop',
)