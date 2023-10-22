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

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
pdfmetrics.registerFont(TTFont('Barlow-Regular', '/usr/share/fonts/Barlow-Regular.ttf'))
pdfmetrics.registerFont(TTFont('Barlow-Bold', '/usr/share/fonts/Barlow-Bold.ttf')) 
pdfmetrics.registerFont(TTFont('Barlow-Medium', '/usr/share/fonts/Barlow-Medium.ttf'))

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
        output_path = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/testing.json"
        target = HTTPSTesting.target
        
        # Run testssl.sh
        try:
            subprocess.run([testssl, option, output_path, target])
            print("Testing Done")
            self.btn_createReportHttps.setEnabled(True)
            HTTPSTesting.read_output_json(self)
        except Exception as e:
            print("Error: " + str(e))
            subprocess.run(["rm", "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/testing.json"])

    def read_output_json(self):
        print("Reading JSON")
        json_file_path = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/testing.json"
        # Load the JSON data from the file
        try:
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
                    result = result["finding"]

                else:
                    print("Finding with ID {} not found.".format(summary))
                    result = "-"

                if "cert_commonName" in summary:
                    self.label_result_DomainName.setText(result) if result != "not offered" else self.label_result_DomainName.setText("No")
                elif "HSTS" in summary:
                    self.label_result_STS.setText(result) if result != "not offered" else self.label_result_STS.setText("No")
                elif "cert_expirationStatus" in summary:
                    self.label_result_Expiration.setText(result) if result != "expired" else self.label_result_Expiration.setText("Expired")
                elif "intermediate_cert_badOCSP" in summary:
                    self.label_Result_CertOCSP.setText(result) if result != "not offered" else self.label_Result_CertOCSP.setText("No")
                elif "cert_signatureAlgorithm" in summary:
                    self.label_Result_Signature.setText(result) if result != "weak" else self.label_Result_Signature.setText("Weak")
                elif "certificate_transparency" in summary:
                    self.label_Result_Transparency.setText(result) if result != "not offered" else self.label_Result_Transparency.setText("No")

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
                        self.label_ResultSSLv2Https.setText("Yes")
                        self.label_ResultSSLv2Https.setStyleSheet("color: red")

                elif protocol == "SSLv3":
                    #self.label_ResultSSLv3Https.setText(result["finding"])
                    if result["finding"] == "not offered":
                        self.label_ResultSSLv3Https.setText("No")
                        self.label_ResultSSLv3Https.setStyleSheet("color: black")
                    else:
                        self.label_ResultSSLv3Https.setText("Yes")
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
        except Exception as e:
            print("Error: " + str(e))
        # Remove JSON file
        subprocess.run(["rm", "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/testing.json"])

    def get_finding_by_id(findings, target_id):
        for finding in findings:
            if finding["id"] == target_id:
                return finding
        return None  # Return None if not found
    
    def validate_input(self, target):
        has_special = any(char in "<>!@#$%^&*()_+-=?&" for char in target)
        if target == "127.0.0.1" or target == "localhost":
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
            return "error"
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
            return "error"
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
        # Get Data from the ui
        target = self.lineEdit_https.text()
        domain_name = self.label_result_DomainName.text()
        sts = self.label_result_STS.text()
        cert_ocsp = self.label_Result_CertOCSP.text()
        signature = self.label_Result_Signature.text()
        expiration = self.label_result_Expiration.text()
        transparency = self.label_Result_Transparency.text()
        sslv2 = self.label_ResultSSLv2Https.text()
        sslv3 = self.label_ResultSSLv3Https.text()
        tls1 = self.label_ResultTLS1Https.text()
        tls11 = self.label_ResultTLS11Https.text()
        tls12 = self.label_ResultTLS12Https.text()
        tls13 = self.label_ResultTLS13Https.text()
        poodle = self.label_resultPoodleHttps.text()
        drown = self.label_resultDrownHttps.text()
        beast = self.label_resultBeastHttps.text()
        heartbleed = self.label_resultHeartBleedHttps.text()
        sweet32 = self.label_resultSweet32Https.text()
        lucky13 = self.label_resultLuck13Https.text()
        
        # Create a PDF canvas
        file_name = f"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/Reports/HTTPS_Testing_Report.pdf"
        self.btn_file_email_https.setText(file_name.split('/')[-1])

        c = canvas.Canvas(file_name, pagesize=A4)
    
        # Define colors
        header_color = colors.HexColor('#A7B6D2')  # Light blue
        title_color = colors.HexColor('#0086D5')   # Dark blue
        text_color = colors.black
        table_color = colors.HexColor('#f1f1f1')
        # First Page
        font_size = 12

        # Header section
        header_text = "| ISAN Security Gizmo Box |"
        c.setFont("Barlow-Regular", font_size)
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
        https_text = "Hypertext Transfer Protocol Secure Testing Report"
        c.setFont("Barlow-Medium", 20)
        c.setFillColor(text_color)
        https_x = (A4[0] - c.stringWidth(https_text)) / 2
        https_y = img_y - 30
        c.drawString(https_x, https_y, https_text)

        # Subtitle and current date
        gizmo_text = "                      ISAN Security Gizmo Box"
        gizmo_x = (A4[0] - c.stringWidth(gizmo_text, "Barlow-Medium", 20)) / 2
        gizmo_y = https_y - 30

        current_datetime = datetime.now().strftime("%d %B %Y %I:%M %p")
        c.setFont("Barlow-Medium", 15)
        date_x = (A4[0] - c.stringWidth(current_datetime,)) / 2
        date_y = gizmo_y - 30

        #c.setFont("Barlow-Regular", 20)
        c.drawString(gizmo_x, gizmo_y, gizmo_text)
        #c.setFont("Barlow-Regular", 15)
        c.drawString(date_x, date_y, current_datetime)

        # Start a new page (Second Page)
        c.showPage()
        # Second Page Content
        # Redraw the header on the second page
        c.setFont("Barlow-Regular", font_size)
        c.setFillColor(header_color)
        c.drawString(72, A4[1] - 36, header_text)
        
        # Add the "Scan Summary : https://example.com" at the center of the page.
        vulner_summary_text = f"Scan Summary : {target}"
        c.setFont("Barlow-Bold", 16)
        c.setFillColor(title_color)  # Set the text color to dark blue
        text_width = c.stringWidth(vulner_summary_text, "Barlow-Regular", 16)
        text_x = (A4[0] - text_width) / 2
        text_y = (A4[1] - 100)  # Adjust the y-coordinate as needed to center it vertically.

        c.drawString(text_x, text_y, vulner_summary_text)

        # Add the current date and time below the "Scan Summary" text
        date_time_text = datetime.now().strftime("%d %B %Y %I:%M %p")
        c.setFont("Barlow-Bold", 12)
        date_time_x = (A4[0] - c.stringWidth(date_time_text, "Barlow-Regular", 12)) / 2
        date_time_y = text_y - 20  # Adjust the vertical position as needed

        c.drawString(date_time_x, date_time_y, date_time_text)

        nmap_info_text = """        testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers,"""
        c.setFont("Barlow-Regular", 9)
        c.setFillColor(text_color)
        nmap_info_x = 72
        nmap_info_y = date_time_y - 30  # Adjust the vertical position as needed
        c.drawString(nmap_info_x, nmap_info_y, nmap_info_text)

        nmap_info_text = """ protocols as well as some cryptographic flaws. """
        nmap_info_y -= 12  # ลดระยะห่างในแนวดิดของบรรทัด
        c.drawString(nmap_info_x, nmap_info_y, nmap_info_text)

        # Redraw the header on the second page
        c.setFont("Barlow-Regular", font_size)
        c.setFillColor(header_color)
        c.drawString(72, A4[1] - 36, header_text)

        # Define a function to create a section with title and table
        def create_section(data, title_color, col_widths, row_heights, y_offset):
            title_font_size = 14
            title_x = 72
            title_y = A4[1] - 30 - 2 * cm - y_offset
            c.setFont("Barlow-Regular", title_font_size)
            c.setFillColor(title_color)
        

            table = Table(data, colWidths=col_widths, rowHeights=row_heights)
            table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Barlow-Medium'),
                ('BOTTOMPADDING', (0, -1), (0, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, table_color)
            ]))
            table.wrapOn(c, 0, 0)
            table.drawOn(c, 80, title_y - 160)

        # Head Table 1
        test_text = "Testing Summary"
        c.setFont("Barlow-Medium", 12)
        c.setFillColor(title_color)
        test_text_x = 72 
        test_text_y = A4[1] - 210  # ระบุตำแหน่งแนวราบด้านล่างของหัวข้อ

        c.drawString(test_text_x, test_text_y, test_text)
        # Section 1: Testing Summary
        testing_summary_data = [
            ['Domain name', domain_name],
            ['Strict Transport Security', sts],
            ['Certificate Expiration', expiration],
            ['Certificate OCSP', cert_ocsp],
            ['Signature Algorithm', signature],
            ['Certificate Transparency', transparency],
        ]
        col_widths = [200] * 2
        row_heights = [20] * len(testing_summary_data)
        create_section(testing_summary_data, title_color, col_widths, row_heights, 120)

        # Head Table 2
        pro_text = "Testing Protocols"
        c.setFont("Barlow-Medium", 12)
        c.setFillColor(title_color)
        pro_text_x = 72 
        pro_text_y = A4[1] - 390  # ระบุตำแหน่งแนวราบด้านล่างของหัวข้อ
        c.drawString(pro_text_x, pro_text_y, pro_text)
        # Section 2: Testing Protocols
        testing_protocols_data = [
            ['SSV v2', sslv2],
            ['SSV v3', sslv3],
            ['TLS 1', tls1],
            ['TLS 1.1', tls11],
            ['TLS 1.2', tls12],
            ['TLS 1.3', tls13]
        ]
        col_widths = [200] * 2
        row_heights = [20] * len(testing_protocols_data)
        create_section(testing_protocols_data, title_color, col_widths, row_heights, y_offset= 280)

        # Head Table 3
        vul_text = "Testing Vulnerabilities"
        c.setFont("Barlow-Medium", 12)
        c.setFillColor(title_color)
        vul_text_x = 72 
        vul_text_y = A4[1] - 550  # ระบุตำแหน่งแนวราบด้านล่างของหัวข้อ
        c.drawString(vul_text_x, vul_text_y, vul_text)
        # Section 3: Testing Vulnerabilities
        testing_vulnerabilities_data = [
            ['POODLE (SSL v3)', poodle],
            ['DROWN', drown],
            ['BEAST', beast],
            ['Heartbleed', heartbleed],
            ['SWEET32', sweet32],
            ['LUCKY13', lucky13]
        ]
        col_widths = [200] * 2
        row_heights = [20] * len(testing_vulnerabilities_data)
        create_section(testing_vulnerabilities_data, title_color, col_widths, row_heights, y_offset= 440)

        # Save the PDF
        c.save()

        HTTPSTesting.convert_pdf_to_png(self)

    def send_email(self):
        self.btn_sendReport_email_https.setText("Sending...")

        to_receiver_email = self.lineEdit_to_email_https.text()
        subject_receiver = self.lineEdit_subject_email_https.text()
        body = self.textEdit_body_email_https.toPlainText()
        file = "/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/Reports/HTTPS_Testing_Report.pdf"
        
        # if send email success then remove file
        SendEmail.sending(SendEmail, to_receiver_email, subject_receiver, body, file)
        HTTPSTesting.remove_file(self, file)
    
    def remove_file(self, file):
        # remove png
        for i in range(10):
            subprocess.run(["rm", f"/home/kali/Desktop/Linux-ISAN-Security-Gizmo-Box/data/ImagesfromPDF/output_page_https_{i}.png"])

        # remove pdf
        subprocess.run(["rm", file])
    
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



