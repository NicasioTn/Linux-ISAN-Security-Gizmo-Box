import subprocess
import sys
from setuptools import setup, find_packages
# pip install PyMuPDF pyqt6-tools PyQt6-Qt6 reportlab configparser requests qrcode
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyMuPDF', 'pyqt6-tools', 'PyQt6-Qt6', 'reportlab', 'configparser', 'requests', 'qrcode'])