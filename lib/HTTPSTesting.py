import json
from PyQt6.QtWidgets import QDialog
from SendEmail import *
import PyQt6.QtGui as QtGui

import subprocess
import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
from reportlab.lib.units import cm
from reportlab.platypus import Table, TableStyle
from reportlab.lib.utils import ImageReader


class HTTPSTesting(QDialog):

    target = ""
    test_summary = [
        "cert_commonName",
        "HSTS",
        "cert_expirationStatus",
        "intermediate_cert_badOCSP",
        "cert_signatureAlgorithm",
        "certificate_transparency",
    ]

    protocols_list = [
        "SSLv2",
        "SSLv3",
        "TLS1",
        "TLS1_1",
        "TLS1_2",
        "TLS1_3",
    ]

    vuln_list = [
        "POODLE_SSL",
        "DROWN",
        "BEAST",
        "heartbleed",
        "SWEET32",
        "LUCKY13",
    ]

    def __init__(self):
        #super(HTTPSTesting, self).__init__()
        super().__init__()

    def clear(self):
        self.lineEdit_https.setText('')
        self.btn_scanHttps.setEnabled(True)
        HTTPSTesting.label_clear(self)
    
    def label_clear(self):
        # Testing Summary
        self.label_result_DomainName.setText('')
        self.label_result_STS.setText('')  
        self.label_Result_CertOCSP.setText('')
        self.label_Result_Signature.setText('')
        self.label_result_Expiration.setText('')
        self.label_Result_Transparency.setText('')

        # Testing Protocols
        self.label_ResultTLS1Https.setText('')
        self.label_ResultSSLv2Https.setText('')
        self.label_ResultSSLv3Https.setText('')
        self.label_ResultTLS11Https.setText('')
        self.label_ResultTLS12Https.setText('')
        self.label_ResultTLS13Https.setText('')

        # Testing Vulnerabilities
        self.label_resultPoodleHttps.setText('')
        self.label_resultDrownHttps.setText('')
        self.label_resultBeastHttps.setText('')
        self.label_resultHeartBleedHttps.setText('')
        self.label_resultSweet32Https.setText('')
        self.label_resultLuck13Https.setText('')
    
    def checkHTTPS(self):
        text = self.lineEdit_https.text()
        target = HTTPSTesting.validate_input(self, text)
        HTTPSTesting.target = target
            
    def scanHTTPS(self):
        HTTPSTesting.label_clear(self)
        target = HTTPSTesting.target
        print("Starting Testing " + target)
        self.btn_scanHttps.setEnabled(False)
        self.btn_createReportHttps.setEnabled(False)

        testssl = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/testssl.sh/testssl.sh" 
        option = "--jsonfile"
        output_path = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/output_testssl/testing.json"
        target = HTTPSTesting.target
        
        # Run testssl.sh
        subprocess.run([testssl, option, output_path, target])
        print("Testing Done")
        self.btn_createReportHttps.setEnabled(True)
        HTTPSTesting.read_output_json(self)

    def read_output_json(self):
        print("Reading JSON")
        json_file_path = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/output_testssl/testing.json"
        # Load the JSON data from the file
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
        
        results = []

        for entry in data:
            result = {
                "id": entry.get("id", ""),
                "ip": f"{entry.get('ip', 'Unknown')}",
                "port": entry.get("port", ""),
                "severity": entry.get("severity", ""),
                "finding": entry.get("finding", "")
            }
            results.append(result)

        print("Reading JSON Done")

        # ----------------- Testing Summary -----------------
        print("Test Summary:")
        for summary in HTTPSTesting.test_summary:
            result = HTTPSTesting.get_finding_by_id(data, summary)
            if result is not None:
                print("Finding for ID {}: {}".format(summary, result["finding"]))
            else:
                print("Finding with ID {} not found.".format(summary))

            if summary == "cert_commonName":
                self.label_result_DomainName.setText(result["finding"])
            elif summary == "HSTS":
                self.label_result_STS.setText(result["finding"]) 
            elif summary == "cert_expirationStatus":
                self.label_result_Expiration.setText(result["finding"])
            elif summary == "intermediate_cert_badOCSP":
                self.label_Result_CertOCSP.setText(result["finding"])
            elif summary == "cert_signatureAlgorithm":
                self.label_Result_Signature.setText(result["finding"])
            elif summary == "certificate_transparency":
                self.label_Result_Transparency.setText(result["finding"])

        # ----------------- Testing Protocols -----------------
        print("Testing Protocols:")
        for protocol in HTTPSTesting.protocols_list:
            result = HTTPSTesting.get_finding_by_id(data, protocol)
            if result is not None:
                print("Finding for ID {}: {}".format(protocol, result["finding"]))
            else:
                print("Finding with ID {} not found.".format(protocol))

            if protocol == "SSLv2":
                #self.label_ResultSSLv2Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultSSLv2Https.setText("No")
                    self.label_ResultSSLv2Https.setStyleSheet("color: black")
                else:
                    self.label_ResultSSLv2Https.setStyleSheet("color: red")

            elif protocol == "SSLv3":
                #self.label_ResultSSLv3Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultSSLv3Https.setText("No")
                    self.label_ResultSSLv3Https.setStyleSheet("color: black")
                else:
                    self.label_ResultSSLv3Https.setStyleSheet("color: red")

            elif protocol == "TLS1":
                #self.label_ResultTLS1Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultTLS1Https.setText("No")
                    self.label_ResultTLS1Https.setStyleSheet("color: black")
                else:
                    self.label_ResultTLS1Https.setText("Yes")
                    self.label_ResultTLS1Https.setStyleSheet("color: green")

            elif protocol == "TLS1_1":
                #self.label_ResultTLS11Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultTLS11Https.setText("No")
                    self.label_ResultTLS11Https.setStyleSheet("color: black")
                else:
                    self.label_ResultTLS11Https.setText("Yes")
                    self.label_ResultTLS11Https.setStyleSheet("color: green")
                
            elif protocol == "TLS1_2":
                #self.label_ResultTLS12Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultTLS12Https.setText("No")
                    self.label_ResultTLS12Https.setStyleSheet("color: black")
                else:
                    self.label_ResultTLS12Https.setText("Yes")
                    self.label_ResultTLS12Https.setStyleSheet("color: green")
                    
            elif protocol == "TLS1_3":
                #self.label_ResultTLS13Https.setText(result["finding"])
                if result["finding"] == "not offered":
                    self.label_ResultTLS13Https.setText("No")
                    self.label_ResultTLS13Https.setStyleSheet("color: red")
                else:
                    self.label_ResultTLS13Https.setText("Yes")
                    self.label_ResultTLS13Https.setStyleSheet("color: green")

        # ----------------- Testing Vulnerabilities -----------------
        print("Testing Vulnerabilities:")
        for vuln in HTTPSTesting.vuln_list:
            result = HTTPSTesting.get_finding_by_id(data, vuln)
            if result is not None:
                print("Finding for ID {}: {}".format(vuln, result["finding"]))
            else:
                print("Finding with ID {} not found.".format(vuln))

            if vuln == "POODLE_SSL":
                if "not vulnerable" in result["finding"]:
                    self.label_resultPoodleHttps.setText("No")
                    self.label_resultPoodleHttps.setStyleSheet("color: green")
                else:
                    self.label_resultPoodleHttps.setText("Yes")
                    self.label_resultPoodleHttps.setStyleSheet("color: red")
            
            elif vuln == "DROWN":
                if "not vulnerable" in result["finding"]:
                    self.label_resultDrownHttps.setText("No")
                    self.label_resultDrownHttps.setStyleSheet("color: green")
                else:
                    self.label_resultDrownHttps.setText("Yes")
                    self.label_resultDrownHttps.setStyleSheet("color: red")
            
            elif vuln == "BEAST":
                if "not vulnerable" in result["finding"]:
                    self.label_resultBeastHttps.setText("No")
                    self.label_resultBeastHttps.setStyleSheet("color: green")
                else:
                    self.label_resultBeastHttps.setText("Yes")
                    self.label_resultBeastHttps.setStyleSheet("color: red")
            
            elif vuln == "heartbleed":
                if "not vulnerable" in result["finding"]:
                    self.label_resultHeartBleedHttps.setText("No")
                    self.label_resultHeartBleedHttps.setStyleSheet("color: green")
                else:
                    self.label_resultHeartBleedHttps.setText("Yes")
                    self.label_resultHeartBleedHttps.setStyleSheet("color: red")
            
            elif vuln == "SWEET32":
                if "not vulnerable" in result["finding"]:
                    self.label_resultSweet32Https.setText("No")
                    self.label_resultSweet32Https.setStyleSheet("color: green")
                else:
                    self.label_resultSweet32Https.setText("Yes")
                    self.label_resultSweet32Https.setStyleSheet("color: red")
            
            elif vuln == "LUCKY13":
                if "not vulnerable" in result["finding"]:
                    self.label_resultLuck13Https.setText("No")
                    self.label_resultLuck13Https.setStyleSheet("color: green")
                else:
                    self.label_resultLuck13Https.setText("Yes")
                    self.label_resultLuck13Https.setStyleSheet("color: red")

        # Remove JSON file
        subprocess.run(["rm", "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/output_testssl/testing.json"])

    def get_finding_by_id(findings, target_id):
        for finding in findings:
            if finding["id"] == target_id:
                return finding
        return None  # Return None if not found
    
    def validate_input(self, target):
        has_special = any(char in "<>!@#$%^&*()_+-=?&" for char in target)
        if has_special:
            print("Special Characters Detected")
            self.lineEdit_https.setPlaceholderText("Invalid Input")
            # wait 2 seconds
            self.lineEdit_https.setStyleSheet('''QLineEdit {
  border: 2px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}''')
            self.lineEdit_https.setText('')
            return False
        else:
            self.lineEdit_https.setStyleSheet('''QLineEdit {
  border: 2px solid green;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}''')
            return target.lower()
        
    def createReport(self):
        # Create a PDF canvas
        current_time = datetime.now()
        file_name = f"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/Reports/HTTPS_Testing_Report.pdf"
        self.btn_file_email_https.setText(file_name.split('/')[-1])
        target = self.lineEdit_https.text()

        c = canvas.Canvas(file_name, pagesize=A4)
        
        # Define colors
        header_color = colors.HexColor('#A7B6D2')  # Light blue
        title_color = colors.HexColor('#0086D5')   # Dark blue
        text_color = colors.black

        # First Page
        font_size = 12

        # Header section
        header_text = "| ISAN Security Gizmo Box |"
        c.setFont("Helvetica", font_size)
        c.setFillColor(header_color)
        c.drawString(72, A4[1] - 36, header_text)

        # Logo and main title
        image_path = '/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/assets/images/report_logo.png'
        img = ImageReader(image_path)
        img_width, img_height = 250, 200
        img_x = (A4[0] - img_width) / 2
        img_y = (A4[1] - img_height) / 2 + 3 * cm

        c.drawImage(img, img_x, img_y, width=img_width, height=img_height)

        # Main title
        malware_text = "Hypertext Transfer Protocol Secure Testing Report"
        c.setFont("Helvetica", 20)
        c.setFillColor(text_color)
        malware_x = (A4[0] - c.stringWidth(malware_text, "Helvetica", 20)) / 2
        malware_y = img_y - 20
        c.drawString(malware_x, malware_y, malware_text)

        # Subtitle and current date
        gizmo_text = "ISAN Security Gizmo Box"
        gizmo_x = (A4[0] - c.stringWidth(gizmo_text, "Helvetica", 20)) / 2
        gizmo_y = malware_y - 50

        current_datetime = datetime.now().strftime("%d %B %Y %I:%M %p")
        c.setFont("Helvetica", 15)
        date_x = (A4[0] - c.stringWidth(current_datetime, "Helvetica", 15)) / 2
        date_y = gizmo_y - 50

        c.setFont("Helvetica", 20)
        c.drawString(gizmo_x, gizmo_y, gizmo_text)
        c.setFont("Helvetica", 15)
        c.drawString(date_x, date_y, current_datetime)

        # Start a new page (Second Page)
        c.showPage()

        # Redraw the header on the second page
        c.setFont("Helvetica", font_size)
        c.setFillColor(header_color)
        c.drawString(72, A4[1] - 36, header_text)

        # Define a function to create a section with title and table
        def create_section(title, data, title_color, col_widths, row_heights, y_offset):
            title_font_size = 14
            title_x = 72
            title_y = A4[1] - 30 - 2 * cm - y_offset
            c.setFont("Helvetica", title_font_size)
            c.setFillColor(title_color)
            c.drawString(title_x, title_y, title)
            c.line(title_x, title_y - 3, title_x + c.stringWidth(title, "Helvetica", title_font_size), title_y - 3)

            table = Table(data, colWidths=col_widths, rowHeights=row_heights)
            table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('BOTTOMPADDING', (0, -1), (0, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, text_color)
            ]))
            table.wrapOn(c, 0, 0)
            table.drawOn(c, 80, title_y - 170)

        # Section 1: Testing Summary
        testing_summary_data = [
            ['Domain name', 'isanmsu.com'],
            ['Strict Transport Security', 'No HSTS header'],
            ['Server banner', 'Apache/2'],
            ['Signature Algorithm', 'SHA256 with RSA'],
            ['Certificate Transparency', 'Yes (certificate)'],
            ['Certificates provided', '2 (2403 bytes)'],
            ['Issuer', 'ISRG Root X1']
        ]
        col_widths = [200] * 2
        row_heights = [20] * 7 
        create_section("Testing Summary", testing_summary_data, title_color, col_widths, row_heights, 0)

        # Section 2: Testing Protocols
        testing_protocols_data = [
            ['SSV v2', 'No'],
            ['SSV v3', 'No'],
            ['TLS 1', 'No'],
            ['TLS 1.1', 'No'],
            ['TLS 1.2', 'Yes'],
            ['TLS 1.3', 'Yes']
        ]
        col_widths = [200] * 2
        row_heights = [20] * 6 
        create_section("Testing Protocols", testing_protocols_data, title_color, col_widths, row_heights, 200)

        # Section 3: Testing Vulnerabilities
        testing_vulnerabilities_data = [
            ['POODLE (SSL v3)', 'No, SSL 3 not supported'],
            ['DROWN', 'No'],
            ['BEAST', 'No'],
            ['Heartbleed', 'No, no Heartbleed extension'],
            ['SWEET32', 'No'],
            ['LUCKY13', 'No']
        ]
        col_widths = [200] * 2
        row_heights = [20] * 6 
        create_section("Testing Vulnerabilities", testing_vulnerabilities_data, title_color, col_widths, row_heights, 400)

        # Save the PDF
        c.save()

        HTTPSTesting.convert_pdf_to_png(self)

    def send_email(self):
        self.btn_sendReport_email_https.setText("Sending...")

        to_receiver_email = self.lineEdit_to_email_https.text()
        subject_receiver = self.lineEdit_subject_email_https.text()
        body = self.textEdit_body_email_https.toPlainText()
        file = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/Reports/HTTPS_Testing_Report.pdf"
        
        SendEmail.sending(SendEmail, to_receiver_email, subject_receiver, body, file)
    
    def convert_pdf_to_png(self):
        import os
        import fitz

        # Path to PDF file
        pdf_file = r"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/Reports/HTTPS_Testing_Report.pdf"

        # Open PDF file
        pdf_doc = fitz.open(pdf_file)

        # Output directory
        output_dir = r"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/ImagesfromPDF/"  # Corrected path

        # Iterate through pages and convert to PNG
        for page_number, page in enumerate(pdf_doc):
            pix = page.get_pixmap()
            output_file = os.path.join(output_dir, f"output_page_https_{page_number}.png")
            pix.save(output_file, "png")

        # Close PDF file
        pdf_doc.close()

        self.label_Report_https.setPixmap(QtGui.QPixmap("/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/ImagesfromPDF/output_page_https_0.png"))
        self.label_countPageReport_https.setText("0")

    def set_pdf_viewer(self, step):
        page_number = self.label_countPageReport_https.text()
        min_page = 0

        number = 0
        if step == "next":
            number = int(page_number) + 1
        elif step == "back":
            number = int(page_number) - 1
            number = max(number, min_page)
        else:
            number = 0

        self.label_countPageReport_https.setText(str(number))
        self.label_Report_https.setPixmap(QtGui.QPixmap(f"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/ImagesfromPDF/output_page_https_{number}.png"))



