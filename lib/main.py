import sys
import configparser

from PyQt6.QtWidgets import ( QApplication, QLineEdit, QMainWindow )
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.uic import loadUi

# Import all the classes from the lib folder
from PasswordEvaluation import *
from MessageDigest import *
from MalwareScanning import *
from VulnerabilityScanning import *
from HTTPSTesting import *

class Main(QMainWindow):
    
    def __init__(self):
        super(Main, self).__init__()
        loadUi("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/ui/mainWindow.ui", self)
         
        # initialize Icon
        self.setWindowTitle("ISAN Security Gizmo Box v1.0")
        self.setWindowIcon(QIcon("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/icon_gixmobox.png"))
        self.hide_icon = QIcon("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/icon_closedeye.png")
        self.unhide_icon = QIcon("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/icon_openeye.png")
        self.warning_icon = QIcon("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/warning-red.png")
        self.check_icon = QIcon("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/Checked.png")
        self.label_logo = QPixmap("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/icons/icon_gixmobox.png")
        self.image_main = QPixmap("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/images/main.png")

        # Event Back Button
        self.btn_backAdvancedUser.clicked.connect(self.openHomePage)
        self.btn_backPassword.clicked.connect(self.openAdvancedUserHome)
        self.btn_backDict.clicked.connect(self.PasswordEvaluationHome)
        self.btn_backMalware.clicked.connect(self.openAdvancedUserHome)
        self.btn_backMSDigest.clicked.connect(self.openAdvancedUserHome)
        self.btn_backNetworkUser.clicked.connect(self.openHomePage)
        self.btn_backVulner.clicked.connect(self.openNetworkUserHome)
        self.btn_backHttps.clicked.connect(self.openNetworkUserHome)
        self.btn_backSettings.clicked.connect(self.openHomePage)
        self.btn_backEmail_malware.clicked.connect(self.openMalwareHome)
        self.btn_backEmail_vulner.clicked.connect(self.openVulnerabilityHome)
        self.btn_backEmail_https.clicked.connect(self.openHttpsHome)
        
        # clear cache data after back button
        self.btn_backPassword.clicked.connect(lambda: PasswordEvaluation.clear(self))
        self.btn_backDict.clicked.connect(lambda: PasswordAttack.back_for_password_attack(self))
        self.btn_backMalware.clicked.connect(lambda: MalwareScanning.clear(self))
        self.btn_backMSDigest.clicked.connect(lambda: MessageDigest.clear(self))
        self.btn_backVulner.clicked.connect(lambda: VulnerabilityScanning.clear(self))
        self.btn_backHttps.clicked.connect(lambda: HTTPSTesting.clear(self))
        self.btn_backEmail_malware.clicked.connect(lambda: MalwareScanning.clear(self))
        self.btn_backEmail_vulner.clicked.connect(lambda: VulnerabilityScanning.clear(self))
        self.btn_backEmail_https.clicked.connect(lambda: HTTPSTesting.clear(self))
        
        # --------------------- Get Started ---------------------------------
        self.btn_getStart.clicked.connect(self.openHomePage)

        # --------------------- Setting -----------------------------------
        self.btn_settings.clicked.connect(self.openSettings)
        self.btn_saveSettings.clicked.connect(self.saveSetting)
        self.btn_removeLineAPISettings.clicked.connect(self.removeline_api_key)
        self.btn_removeVirusTotalAPISettings.clicked.connect(self.removevirustotal_api_key)
        
        # -------------------- Home ---------------------------------------
        self.btn_home.clicked.connect(lambda: self.stackedWidget.setCurrentWidget(self.mainpage))
        self.btn_home.clicked.connect(lambda: PasswordEvaluation.clear(self))
        self.btn_home.clicked.connect(lambda: PasswordAttack.clear(self))
        self.btn_home.clicked.connect(lambda: MessageDigest.clear(self))
        self.btn_home.clicked.connect(lambda: MalwareScanning.clear(self))
        self.btn_home.clicked.connect(lambda: VulnerabilityScanning.clear(self))
        self.btn_home.clicked.connect(lambda: HTTPSTesting.clear(self))

        self.btn_advancedUserHome.clicked.connect(self.openAdvancedUserHome)
        self.btn_networkUserHome.clicked.connect(self.openNetworkUserHome)

        # -------------------- Advance User ---------------------------------
        self.btn_advancedUserHome.clicked.connect(self.openAdvancedUserHome)
        # ------------------------------------------------------------------
        self.btn_password.clicked.connect(self.PasswordEvaluationHome)
        self.btn_malware.clicked.connect(self.openMalwareHome)
        self.btn_MSdigest.clicked.connect(self.openMessageDigestHome)

        # --------------------- Network User --------------------------------
        self.btn_networkUserHome.clicked.connect(self.openNetworkUserHome)
        # ------------------------------------------------------------------
        self.btn_vulner.clicked.connect(self.openVulnerabilityHome)
        self.btn_hsts.clicked.connect(self.openHttpsHome)

        ### --------------------- Password Evaluation -------------------------
        PasswordEvaluation.init(self) # Initialize the password evaluation page
        PasswordEvaluation.LoadWordlist(self) # Load the wordlist from the file

        # Initialize the password field
        self.btn_showPassword.setIcon(self.hide_icon)
        self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Password)
        
        # Detect changes in the password field
        self.lineEdit_password.textChanged.connect(lambda: PasswordEvaluation.getPassword(self))
        self.lineEdit_password.textChanged.connect(lambda: PasswordEvaluation.check_password(self))

        # Event Button Page Password Evaluation
        self.btn_showPassword.clicked.connect(lambda: PasswordEvaluation.show_hide_password(self))
        self.btn_dictAttack.clicked.connect(self.Passowrd_Dictionary_Attack)
        self.btn_infoEntropy.clicked.connect(lambda: PasswordEvaluation.infoEntropy(self))

        ### --------------------- Dictionary Attack -------------------------
        
        # Event Button Page Dictionary Attack
        self.btn_browseDict.clicked.connect(lambda: PasswordAttack.open_file_wordlist(self))
        self.btn_clearDict.clicked.connect(lambda: PasswordAttack.clear(self))
        self.btn_showPasswordDict.clicked.connect(lambda: PasswordAttack.show_hide_password(self))
        self.dropdown_wordLists.activated.connect(lambda: PasswordAttack.select_wordlists(self))
        self.btn_start_attack.clicked.connect(lambda: PasswordAttack.start_attack(self))
        self.lineEdit_inputFileDict.textChanged.connect(lambda: PasswordAttack.check_wordlist(self))
        PasswordAttack.show_loadding(self)

        ### --------------------- Message Digest ------------------------------
        MessageDigest.LoadAPIKey(self) # Load API Key from config file
        self.lineEdit_outputTextMSDigest.textChanged.connect(lambda: MessageDigest.LoadAPIKey(self))
        
        # Event Button Page Message Digest
        self.btn_browseMSDigest.clicked.connect(lambda: MessageDigest.openFileDialog(self))
        self.btn_clearMSDigest.clicked.connect(lambda: MessageDigest.clear(self))
        self.btn_saveQR.clicked.connect(lambda: MessageDigest.saveQRCode(self))
        self.btn_lineAPI.clicked.connect(lambda: MessageDigest.showBtnLine(self, MessageDigest.state_line))
        self.btn_sendMSDigest.clicked.connect(lambda: MessageDigest.processLineKey(self))
        self.btn_copy.clicked.connect(lambda: MessageDigest.copyOutput(self))
        self.btn_infoToken.clicked.connect(lambda: MessageDigest.infoToken(self))
        self.lineEdit_outputTextMSDigest.textChanged.connect(lambda: MessageDigest.qrCodeGenerator(self, self.lineEdit_outputTextMSDigest.text()))
        
        ### --------------------- Malware Scan --------------------------------
        MalwareScanning.show_resultimage(self, type='scan', status='default') # Initialize the image
        MalwareScanning.loadAPIKey(self) # Load API Key from config file
        
        # Event Button Page Malware Scan
        self.btn_scanMalware.clicked.connect(lambda: MalwareScanning.scanMalware(self))
        self.btn_browseMalware.clicked.connect(lambda: MalwareScanning.openFileScanning(self))
        self.btn_clearMalware.clicked.connect(lambda: MalwareScanning.clear(self))
        self.btn_createReport.clicked.connect(self.openSendEmail_malware)
 
        ### --------------------- Vulnerability -------------------------------
        self.textEdit_ResultScan.textChanged.connect(lambda: VulnerabilityScanning.chech_output(self))
        # Event Button Page Vulnerability
        self.btn_scanVulner.clicked.connect(lambda: VulnerabilityScanning.prepareCommand(self))
        self.btn_clearVulner.clicked.connect(lambda: VulnerabilityScanning.clear(self))
        self.dropdown_typeScan.activated.connect(lambda: VulnerabilityScanning.typeScan(self))
        self.lineEdit_vulner.textChanged.connect(lambda: VulnerabilityScanning.validate_input(self, self.lineEdit_vulner.text()))
        self.btn_createReportVulner.clicked.connect(self.openSendEmail_vulner)

        ### --------------------- HTTPS Testing -------------------------------

        # Event Button Page HTTPS Testing
        self.btn_scanHttps.clicked.connect(lambda: HTTPSTesting.scanHTTPS(self))
        self.btn_clearHttps.clicked.connect(lambda: HTTPSTesting.clear(self))
        self.lineEdit_https.textChanged.connect(lambda: HTTPSTesting.checkHTTPS(self))
        self.btn_createReportHttps.clicked.connect(self.openSendEmail_https)

        ### --------------------- Send Email ----------------------------------
        self.btn_sendReport_email_malware.clicked.connect(lambda: MalwareScanning.send_email(self))
        self.btn_backReport_malware.clicked.connect(lambda: MalwareScanning.set_pdf_viewer(self, "back"))
        self.btn_nextReport_malware.clicked.connect(lambda: MalwareScanning.set_pdf_viewer(self, "next"))

        self.btn_sendReport_email_vulner.clicked.connect(lambda: VulnerabilityScanning.send_email(self))
        self.btn_backReport_vulner.clicked.connect(lambda: VulnerabilityScanning.set_pdf_viewer(self, "back"))
        self.btn_nextReport_vulner.clicked.connect(lambda: VulnerabilityScanning.set_pdf_viewer(self, "next"))

        self.btn_sendReport_email_https.clicked.connect(lambda: HTTPSTesting.send_email(self))
        self.btn_backReport_https.clicked.connect(lambda: HTTPSTesting.set_pdf_viewer(self, "back"))
        self.btn_nextReport_https.clicked.connect(lambda: HTTPSTesting.set_pdf_viewer(self, "next"))

        
    # -------------------- Home ---------------------------------------
    def openHomePage(self):
        self.stackedWidget.setCurrentWidget(self.mainpage)
    
    # Advanced User ------------------------------------------
    def openAdvancedUserHome(self):
        self.stackedWidget.setCurrentWidget(self.page_advancedUser)

    def PasswordEvaluationHome(self):
        self.stackedWidget.setCurrentWidget(self.page_passwordEvaluation)
        self.btn_dictAttack.setVisible(False)
        self.label_outputSearchNordPass.setText('Start typing to see the entropy score')
    
    def Passowrd_Dictionary_Attack(self):
        self.lineEdit_passwordDict.setText(self.lineEdit_password.text())
        self.stackedWidget.setCurrentWidget(self.page_passwordAttack)
        PasswordAttack.init(self)
    
    def openMalwareHome(self):
        MalwareScanning.show_resultimage(self, type='scan', status='default')
        self.stackedWidget.setCurrentWidget(self.page_malware)

    def openMessageDigestHome(self):
        self.stackedWidget.setCurrentWidget(self.page_messageDigest)
        self.lineEdit_MSdigest.textChanged.connect(lambda: MessageDigest.checkFile_Text(self))
        MessageDigest.showBtnLine(self, False) # Hide the Line Notify button

    # Network User ------------------------------------------
    def openNetworkUserHome(self):
        self.stackedWidget.setCurrentWidget(self.page_networkUser)

    def openVulnerabilityHome(self):
        self.stackedWidget.setCurrentWidget(self.page_vulnerability)
        VulnerabilityScanning.showWellKnownPorts(self)
    
    def openHttpsHome(self):
        self.stackedWidget.setCurrentWidget(self.page_https)
        HTTPSTesting.label_clear(self)

    # Send Email --------------------------------------------
    def openSendEmail_malware(self):
        self.stackedWidget.setCurrentWidget(self.page_malware_email)
        MalwareScanning.createReport(self)
    
    def openSendEmail_vulner(self):
        self.stackedWidget.setCurrentWidget(self.page_vulner_email)
        VulnerabilityScanning.createReport(self)
    
    def openSendEmail_https(self):
        self.stackedWidget.setCurrentWidget(self.page_https_email)
        HTTPSTesting.createReport(self)

    # Setting -----------------------------------------------sa

    def openSettings(self):
        self.stackedWidget.setCurrentWidget(self.page_settings)

        # Initialize the button
        self.btn_removeLineAPISettings.setText('Remove')
        self.btn_removeVirusTotalAPISettings.setText('Remove')
        self.btn_saveSettings.setText('Save')

        # Load Message Digest API Key from file config
        line_api_key = MessageDigest.LoadAPIKey(self)
        self.lineEdit_LineAPISettings.setText(line_api_key)

        # Load Malware API Key from file config
        virustotal_api_key = MalwareScanning.loadAPIKey(self)
        self.lineEdit_virusTotalAPISettings.setText(virustotal_api_key)
    
    def saveSetting(self):
        self.btn_saveSettings.setText('Saved!')
        MessageDigest.saveAPIKey(self, self.lineEdit_LineAPISettings.text())
        MalwareScanning.saveAPIKey(self, self.lineEdit_virusTotalAPISettings.text())

    def removeline_api_key(self):
        self.lineEdit_LineAPISettings.setText('')
        self.btn_removeLineAPISettings.setText('Removed!')
        MessageDigest.saveAPIKey(self, '')
    
    def removevirustotal_api_key(self):
        self.lineEdit_virusTotalAPISettings.setText('')
        self.btn_removeVirusTotalAPISettings.setText('Removed!')
        MalwareScanning.saveAPIKey(self, '')
    
    def update_image(self, pixmap):
        self.image_analysis.setPixmap(pixmap)
        self.image_analysis.setScaledContents(True)
        self.image_analysis.setAlignment(Qt.AlignmentFlag.AlignCenter)

# Run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Main() 
    window.show()

    # Exit the application
    try:
        sys.exit(app.exec())     
    except SystemExit:
        print('Closing Window...')