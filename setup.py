import subprocess
import sys
import os 

#gizmorun = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/GizmoBox.desktop'
desktop = os.path.expanduser("~/Desktop")

# pip install PyMuPDF pyqt6-tools PyQt6-Qt6 reportlab configparser requests qrcode
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyMuPDF', 'pyqt6-tools', 'PyQt6-Qt6', 'reportlab', 'configparser', 'requests', 'qrcode'])

# move the GizmoBox.desktop file to the desktop
#subprocess.run(['mv', gizmorun, desktop])

#clone the testssl.sh repo
subprocess.run(['git', 'clone', 'https://github.com/drwetter/testssl.sh.git'])

testssl_dest = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/'
testssl_souce = '/home/kali/Desktop/testssl.sh'

# move the testssl.sh file to the data folder
subprocess.run(['mv', testssl_souce, testssl_dest])

# create logo.Desktop file with relative path
path = os.getcwd()
logo = path + '/assets/icon_gixmobox.png'
logo_desktop = logo
logo_desktop_file = open(logo_desktop, 'w')
logo_desktop_file.write('[Desktop Entry]\n')
logo_desktop_file.write('Name=logo\n')
logo_desktop_file.write('Exec=' + logo + '\n')
logo_desktop_file.write('Icon=' + logo + '\n')
logo_desktop_file.write('Type=Application\n')
logo_desktop_file.write('Terminal=false\n')
logo_desktop_file.close()

# move the logo.Desktop file to the desktop
subprocess.run(['mv', logo_desktop, desktop])
