import subprocess
import sys
from setuptools import setup, find_packages

gizmorun = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/GizmoBox.desktop'
desktop = '/home/kali/Desktop/'
# pip install PyMuPDF pyqt6-tools PyQt6-Qt6 reportlab configparser requests qrcode
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyMuPDF', 'pyqt6-tools', 'PyQt6-Qt6', 'reportlab', 'configparser', 'requests', 'qrcode'])
subprocess.check_call([sys.executable, 'mv', {gizmorun}, {desktop}])