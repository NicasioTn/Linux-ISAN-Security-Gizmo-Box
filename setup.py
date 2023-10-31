import subprocess
import sys
import os 

desktop = os.path.expanduser("~/Desktop")
gizmorun = os.path.expanduser("~/Desktop/Linux-ISAN-Security-Gizmo-Box/GizmoBox.desktop")

dir_path = os.path.dirname(os.path.realpath(__file__))
# print(dir_path)

# pip install PyMuPDF pyqt6-tools PyQt6-Qt6 reportlab configparser requests qrcode
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyMuPDF', 'pyqt6-tools', 'PyQt6-Qt6', 'reportlab', 'configparser', 'requests', 'qrcode'])

# # move the GizmoBox.desktop file to the desktop
# subprocess.run(['mv', gizmorun, desktop])

#clone the testssl.sh repo
subprocess.run(['git', 'clone', 'https://github.com/drwetter/testssl.sh.git'])

testssl_dest = os.path.expanduser("~/Desktop/Linux-ISAN-Security-Gizmo-Box/data/")
testssl_souce = os.path.expanduser("~/Desktop/testssl.sh/")

# # move the testssl.sh file to the data folder
subprocess.run(['mv', testssl_souce, testssl_dest])

# write file GizmoBox.desktop with relative path
with open(gizmorun, 'w') as f:
    f.write('[Desktop Entry]\n')
    f.write('Version=1.0\n')
    f.write('Type=Application\n')
    f.write('Name=GizmoBox\n')
    f.write('Comment=ISAN Security Gizmo Box\n')
    f.write('Exec=python3 ' + dir_path + '/lib/main.py\n')
    f.write('Icon=' + dir_path + '/assets/icons/icon_gixmobox.png\n')
    f.write('Path=' + dir_path + '\n')
    f.write('Terminal=false\n')
    f.write('StartupNotify=false\n')

# move the GizmoBox.desktop file to the desktop
subprocess.run(['cp', gizmorun, desktop])

# set gio command to allow the GizmoBox.desktop file to be executable
subprocess.run(['gio', 'set', gizmorun, 'metadata::trusted', 'yes'])

# unzip Linux-ISAN-Security-Gizmo-Box/packets/Barlow.zip -d Linux-ISAN-Security-Gizmo-Box/packets/fonts
subprocess.run(['unzip', dir_path + '/packets/Barlow.zip', '-d', dir_path + '/packets/fonts'])

# Auto enter the password for the user from the sudo command
password = b'kali\n'.decode('utf-8')

try:
    subprocess.run(['sudo', 'mv', dir_path + '/packets/fonts/*', '/usr/share/fonts'], input=password, check=True, universal_newlines=True)
except subprocess.CalledProcessError as e:
     print(f"Password is wrong: {e}")

# update the font cache
subprocess.run(['fc-cache', '-f', '-v'])

# unzip Crackstation
subprocess.run(['gunzip', dir_path + '/data/Wordlists/crackstation.txt.gz'])

# cp rockyou.txt
subprocess.run(['cp', '/usr/share/wordlists/rockyou.txt', dir_path + '/data/Wordlists/rockyou.txt'])