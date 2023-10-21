import subprocess
import sys
from setuptools import setup, find_packages

gizmorun = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/GizmoBox.desktop'
desktop = '/home/kali/Desktop/'
# pip install PyMuPDF pyqt6-tools PyQt6-Qt6 reportlab configparser requests qrcode
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyMuPDF', 'pyqt6-tools', 'PyQt6-Qt6', 'reportlab', 'configparser', 'requests', 'qrcode'])

# move the GizmoBox.desktop file to the desktop
subprocess.run(['mv', gizmorun, desktop])

#clone the testssl.sh repo
subprocess.run(['git', 'clone', 'https://github.com/drwetter/testssl.sh.git'])

testssl_dest = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/'
testssl_souce = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/testssl.sh'
# move the testssl.sh file to the data folder
subprocess.run(['mv', testssl_souce, testssl_dest])