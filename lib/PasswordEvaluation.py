import json
import os
import re
from PyQt6.QtCore import QFileInfo
from PyQt6.QtWidgets import QDialog, QFileDialog, QLineEdit
from pathlib import Path
from math import log2
from PyQt6.QtGui import QMovie

class PasswordEvaluation(QDialog):

    hide = True
    maxentropy_to_show = 1024 # 2^1024 is the largest number that can be stored in python
    minentropy = 50
    maxentropy = 80
    minpasswordlength = 8
    nordpass_common_passwords = []

    gizmo_data_path = os.getcwd() + "/data"

    def __init__(self):
        #super(PasswordEvaluation, self).__init__()
        super().__init__()
    
    def init(self):
        # Check if the password field is empty
        if self.lineEdit_password.text() == '':
            self.chk_length.setIcon(self.warning_icon)
            self.chk_numeric.setIcon(self.warning_icon)
            self.chk_upper.setIcon(self.warning_icon)
            self.chk_lower.setIcon(self.warning_icon)
            self.chk_special.setIcon(self.warning_icon)
            self.label_outputSearchNordPass.setText('Start typing to see the entropy score')
            self.label_outputTimeToCrack.setText('0 Seconds')
            self.label_outputPasswordStrength.setText('no password')
            self.label_outputEntropy.setText('0 Bits')
    
    def LoadWordlist(self):
        # Load the list of weak passwords
        with open(f'{PasswordEvaluation.gizmo_data_path}/nordpass_wordlist.json', 'r') as openfile:
            json_object = json.load(openfile)
        
        for item in json_object:
            PasswordEvaluation.nordpass_common_passwords.append(str(item['Password']))
            
    def clear(self):
        self.lineEdit_inputFileDict.setText('')
        self.lineEdit_password.setText('')
        self.lineEdit_passwordDict.setText('')
        self.label_outputSearchNordPass.setText('Start typing to see the entropy score')
        self.label_outputTimeToCrack.setText('0 seconds')
        self.label_outputPasswordStrength.setText('no password')
        self.label_outputEntropy.setText('0 Bits')

    def show_hide_password(self):
        if self.hide == True:
            self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Password) 
            self.hide = False
            self.btn_showPassword.setIcon(self.hide_icon)
            
        else:
            self.lineEdit_password.setEchoMode(QLineEdit.EchoMode.Normal) 
            self.hide = True
            self.btn_showPassword.setIcon(self.unhide_icon)

    def getPassword(self):
        password = PasswordEvaluation.update(self) # Get Password in real time & Check List
        entropy = PasswordEvaluation.calculate_entropy(self, password)
        self.label_outputEntropy.setText(f'{entropy:.0f} Bits')

        # Check if password is in the list of weak passwords
        if entropy == 0:
            self.label_outputEntropy.setText(f'0 Bits')
            self.label_outputPasswordStrength.setText('')
        elif entropy > PasswordEvaluation.maxentropy_to_show: # 1024 bits
            self.label_outputEntropy.setText(f'Almost impossible to crack')
        else:
            self.label_outputEntropy.setText(f'{entropy:.0f} Bits')

        length = len(password)

        if length < 8:
            self.label_outputPasswordStrength.setText('Very Bad')
            self.label_outputPasswordStrength.setStyleSheet("color: rgba(254,61,58,255);"
            "background-color: rgb(237, 236, 237);"
            "border-radius: 20px;")
            self.progressBar_pwdStrength.setValue(10)
            self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                        {
                                                            border: solid;
                                                            border-radius: 30px;
                                                            color: black;
                                                        }
                                                        QProgressBar::chunk 
                                                        {
                                                            background-color:rgba(254,61,58,255);
                                                            border-radius :15px;
                                                        }     ''')
            
            if length == 0: 
                self.label_outputPasswordStrength.setText('')
                self.label_outputEntropy.setText(f'0 Bits')
                self.label_outputPasswordStrength.setStyleSheet("color: gray;"
            "background-color: rgb(237, 236, 237);"
            "border-radius: 20px;")
                self.progressBar_pwdStrength.setValue(0)
                self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                        {
                                                            border: solid;
                                                            border-radius: 30px;
                                                            color: black;
                                                        }
                                                        QProgressBar::chunk 
                                                        {
                                                            background-color: gray;
                                                            border-radius :15px;
                                                        }     ''')

        else : 
            
            # ----- Check Entropy ----- #
            if entropy < PasswordEvaluation.minentropy : # 50 bits
                self.label_outputPasswordStrength.setText('Weak')
                self.label_outputPasswordStrength.setStyleSheet("color: rgba(255,182,0,255);"
            "background-color: rgb(237, 236, 237);"
            "border-radius: 20px;")
                self.progressBar_pwdStrength.setValue(20)
                self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                        {
                                                            border: solid;
                                                            border-radius: 30px;
                                                            color: black;
                                                        }
                                                        QProgressBar::chunk 
                                                        {
                                                            background-color: rgba(255,182,0,255);
                                                            border-radius :15px;
                                                        }     ''')

            elif entropy < PasswordEvaluation.maxentropy : # 80 bits
                self.label_outputPasswordStrength.setText('Medium')
                self.label_outputPasswordStrength.setStyleSheet("color: rgba(0,134,213,255);"
            "background-color: rgb(237, 236, 237);"
            "border-radius: 20px;")
                self.progressBar_pwdStrength.setValue(50)
                self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                        {
                                                            border: solid;
                                                            border-radius: 30px;
                                                            color: black;
                                                        }
                                                        QProgressBar::chunk 
                                                        {
                                                            background-color: rgba(0,134,213,255);
                                                            border-radius :15px;
                                                        }     ''')

            else:
                self.label_outputPasswordStrength.setText('Good')
                self.label_outputPasswordStrength.setStyleSheet("color: rgba(15,152,72,255);"
            "background-color: rgb(237, 236, 237);"
            "border-radius: 20px;")
                self.progressBar_pwdStrength.setValue(100)
                self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                        {
                                                            border: solid;
                                                            border-radius: 30px;
                                                            color: black;
                                                        }
                                                        QProgressBar::chunk 
                                                        {
                                                            background-color: rgba(15,152,72,255);
                                                            border-radius :15px;
                                                        }     ''')
        
        # Show length of password
        self.label_lengthOfPassword.setText(f'{length} Chars')

        # Show time to crack
        self.label_outputTimeToCrack.setText(f'{PasswordEvaluation.time_to_Crack(self, password)}')
        
        # Check if password is in the list of weak passwords
        PasswordEvaluation.check_common_password(self, password, PasswordEvaluation.nordpass_common_passwords)
        
    def check_common_password(self, password, nordpass_common_passwords):
        if password == '':
            self.label_outputEntropy.setText('0 Bits')
            self.label_outputSearchNordPass.setText('Start typing to see the entropy score')
            self.label_outputSearchNordPass.setStyleSheet("color: rgba(0, 143, 255, 255);")
            self.label_outputPasswordStrength.setText('no password')
            self.btn_dictAttack.setVisible(False)
        else:
            if password in nordpass_common_passwords:
                print(PasswordEvaluation.nordpass_common_passwords.index(password))
                self.label_outputSearchNordPass.setText('Found in the top 200 most common passwords by NordPass')
                self.label_outputSearchNordPass.setStyleSheet("color: rgba(254,61,58,255);")
                self.btn_dictAttack.setVisible(False)
                self.label_outputPasswordStrength.setText('Very Bad')
                self.label_outputPasswordStrength.setStyleSheet('''color: rgba(254,61,58,255);
                                                                    background-color: rgb(237, 236, 237);
                                                                    border-radius: 20px;''')
                self.progressBar_pwdStrength.setValue(10)
                self.progressBar_pwdStrength.setStyleSheet('''QProgressBar
                                                            {
                                                                border: solid;
                                                                border-radius: 30px;
                                                                color: black;
                                                            }
                                                            QProgressBar::chunk 
                                                            {
                                                                background-color:rgba(254,61,58,255);
                                                                border-radius :15px;
                                                            }     ''')
            else:
                self.label_outputSearchNordPass.setText('Not found in the lists')
                self.label_outputSearchNordPass.setStyleSheet("color: rgb(8, 120, 41);")
                self.btn_dictAttack.setVisible(True) if self.label_outputSearchNordPass.text() == '' \
                    or self.label_outputSearchNordPass.text() == 'Not found in the lists' else self.btn_dictAttack.setVisible(False)
                
    
    def validate_input(self, password):
        # check password only contains valid characters , a-z, A-Z, 0-9, !@#$%^&*()_+=-, space
        valid_input = re.sub(r'[^a-zA-Z0-9!@#$%^&*()_+=-` ]', '', password)

        # check password not contains a-z, A-Z, 0-9, !@#$%^&*()_+=- 
        if password not in valid_input:
            self.lineEdit_password.setStyleSheet('''QLineEdit {
  border: 1px solid red;
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
}
''')
        else:
            self.lineEdit_password.setStyleSheet('''QLineEdit {
  border: 1px solid gray;
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
}
''')
        return valid_input

    def check_password(self):
        password = self.lineEdit_password.text()

        has_length = len(password) >= PasswordEvaluation.minpasswordlength
        has_numeric = any(char.isdigit() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_lower = any(char.islower() for char in password)
        has_special = any(char in "!@#$%^&*()_+-=" for char in password)

        if has_numeric:
            self.chk_numeric.setIcon(self.check_icon)
        else:
            self.chk_numeric.setIcon(self.warning_icon)
        if has_upper:
            self.chk_upper.setIcon(self.check_icon)
        else:
            self.chk_upper.setIcon(self.warning_icon)
        if has_lower:
            self.chk_lower.setIcon(self.check_icon)
        else:
            self.chk_lower.setIcon(self.warning_icon)
        if has_special:
            self.chk_special.setIcon(self.check_icon)
        else:
            self.chk_special.setIcon(self.warning_icon)
        if has_length:
            self.chk_length.setIcon(self.check_icon)
        else:
            self.chk_length.setIcon(self.warning_icon)


    # real time password detection
    def update(self):
        
        # Reset all checkboxes
        self.chk_length.setChecked(False)
        self.chk_numeric.setChecked(False)
        self.chk_upper.setChecked(False)
        self.chk_lower.setChecked(False)
        self.chk_special.setChecked(False)
        
        # Get password real time
        password = self.lineEdit_password.text()
        # print(password)
        password = PasswordEvaluation.validate_input(self, password)
        for char in password:
            if char.isdigit():
                self.chk_numeric.setChecked(True)
                self.chk_numeric.setIcon(self.check_icon)
            elif char.isupper():
                self.chk_upper.setChecked(True)
                self.chk_upper.setIcon(self.check_icon)
            elif char.islower():
                self.chk_lower.setChecked(True)
                self.chk_lower.setIcon(self.check_icon)
            elif char in '!@#$%^&*()_+-=':
                self.chk_special.setChecked(True)
                self.chk_special.setIcon(self.check_icon)
            else:
                pass
       
        
            if len(self.lineEdit_password.text()) >= PasswordEvaluation.minpasswordlength: # 8 chars
                self.chk_length.setChecked(True)
                self.chk_length.setIcon(self.check_icon)

        return password

    def calculate_entropy(self, password):
        # check if password is empty
        if password == '':
            self.chk_length.setIcon(self.warning_icon)
            self.chk_numeric.setIcon(self.warning_icon)
            self.chk_upper.setIcon(self.warning_icon)
            self.chk_lower.setIcon(self.warning_icon)
            self.chk_special.setIcon(self.warning_icon)
            return 0
    
        # Sum the number of possible characters
        possible_characters = 0
        if self.chk_numeric.isChecked(): # 0-9
            possible_characters += 10
        if self.chk_upper.isChecked(): # A-Z
            possible_characters += 26
        if self.chk_lower.isChecked(): # a-z
            possible_characters += 26
        if self.chk_special.isChecked(): # !@#$%^&*()_+-=
            possible_characters += 32
        if password.isspace() == True: # space
            possible_characters += 1

        # Calculate the entropy using the formula log2(possible_characters^password_length)
        entropy = log2(possible_characters**len(password))
        return entropy
    
    def time_to_Crack(self, password):
        try:
            if password == '':
                self.chk_length.setIcon(self.warning_icon)
                self.chk_numeric.setIcon(self.warning_icon)
                self.chk_upper.setIcon(self.warning_icon)
                self.chk_lower.setIcon(self.warning_icon)
                self.chk_special.setIcon(self.warning_icon)
                return "0 seconds"
        
            possible_characters = 0
            if self.chk_numeric.isChecked(): # 0-9
                possible_characters += 10
            if self.chk_upper.isChecked(): # A-Z
                possible_characters += 26
            if self.chk_lower.isChecked(): # a-z
                possible_characters += 26
            if self.chk_special.isChecked(): # !@#$%^&*()_+-=
                possible_characters += 32
            if password.isspace() == True: # space
                possible_characters += 1

            combinations = possible_characters ** len(password)
            KPS_2020 = 17042497.3 # 17 Million
            
            seconds = combinations / KPS_2020
            seconds = f'{seconds:.0f}'
            seconds = int(seconds)

            # Convert seconds to years, months, weeks, days, hours, minutes, seconds
            minutes, seconds = divmod(seconds, 60)
            hours, minutes = divmod(minutes, 60)
            days, hours = divmod(hours, 24)
            weeks, days = divmod(days, 7)
            months, weeks = divmod(weeks, 4)
            years, months = divmod(months, 12)
            
            time_parts = []
            # Show time to crack all units
            if years > 0:
                time_parts.append(f"{years} year{'s' if years != 1 else ''}")
            if months > 0:
                time_parts.append(f"{months} month{'s' if months != 1 else ''}")
            if weeks > 0:
                time_parts.append(f"{weeks} week{'s' if weeks != 1 else ''}")
            if days > 0:
                time_parts.append(f"{days} day{'s' if days != 1 else ''}")
            if hours > 0:
                time_parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            if minutes > 0:
                time_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
            if seconds > 0:
                time_parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
            if years > 10:
                time_parts = ['more than 10 years']
            if time_parts == []:
                time_parts = ['less than a second']
                
            # Show time to crack 2 largest units
            if len(time_parts) <= 2:
                return " ".join(time_parts)
            
            largest_units = time_parts[:2]
            return " ".join(largest_units)
        
        except OverflowError as e:
            print(f"Error: {e}")
            return "Over 10 years"
        except UnboundLocalError as e:
            print(f"Error: {e}")
    
    def infoEntropy(self):
        import webbrowser
        webbrowser.open('https://www.okta.com/identity-101/password-entropy/')
            
import subprocess
import PyQt6.QtGui as QtGui
import threading
import hashlib
import os
import subprocess
import threading
from PyQt6.QtCore import Qt, pyqtSignal, QObject

class PasswordAttack(QDialog):

    hide = True
    pathdirect_wordlist = None

    def __init__(self):
        #super(PasswordAttack, self).__init__()
        super().__init__()

    def init(self):
        self.btn_start_attack.setEnabled(False)
        self.lineEdit_passwordDict.setEchoMode(QLineEdit.EchoMode.Password)

    def show_hide_password(self):
        if self.hide == True:
            self.lineEdit_passwordDict.setEchoMode(QLineEdit.EchoMode.Password) 
            self.hide = False
            self.btn_showPasswordDict.setIcon(self.hide_icon)
            
        else:
            self.lineEdit_passwordDict.setEchoMode(QLineEdit.EchoMode.Normal) 
            self.hide = True
            self.btn_showPasswordDict.setIcon(self.unhide_icon)

    def clear(self):
        self.lineEdit_inputFileDict.setText('')
        self.lineEdit_inputFileDict.setText('')
        self.dropdown_modeAttack.setCurrentIndex(0)
        self.dropdown_wordLists.setCurrentIndex(0)
        self.textEdit_result_hashcat.clear()
        self.dropdown_modeAttack.setCurrentIndex(0)
        self.dropdown_wordLists.setCurrentIndex(0)
        self.dropdown_wordLists.setEnabled(True)
        self.btn_start_attack.setEnabled(False)
        self.label_focus_output.setText('')
        self.label_focus_output.setStyleSheet("color: black;")

    def back_for_password_attack(self):
        PasswordAttack.clear(self)
        password = self.lineEdit_passwordDict.text()
        PasswordEvaluation.check_common_password(self, password, PasswordEvaluation.nordpass_common_passwords)

    def open_file_wordlist(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self,
           "Open Wordlist File", 
            os.getcwd(),
            "Text Files (*.txt)",
        )
        file_name = QFileInfo(filepath).fileName()
        if filepath:
            # Process the selected filename
            print("Selected file:", filepath)
            
            if filepath:
                path = Path(filepath)
                #self.lineEdit_inputFileDict.setText(str(path)) # show path file
                self.lineEdit_inputFileDict.setText(file_name) # show file name
                PasswordAttack.set_path_wordlist(self, path)
                if path.exists() != True: # check if file exists 
                    print(f"File exists at: {path.exists()}")
                print(f"Get file at: {path}") 
                self.lineEdit_inputFileDict.setText(str(path.name))
                

        return filepath
            
    def check_wordlist(self):
        default_wordlist = ["rockyou.txt", "crackstation.txt"]
        wordlist = self.lineEdit_inputFileDict.text()
        
        # check if wordlist is empty
        if wordlist == '':
            #self.dropdown_wordLists.setCurrentIndex(0)
            self.btn_start_attack.setEnabled(False)
        else:
            self.btn_start_attack.setEnabled(True)

        if wordlist not in default_wordlist:
            self.dropdown_wordLists.setEnabled(False)
            wordlist = PasswordAttack.get_path_wordlist(self)
            return wordlist
        else: 
            wordlist = PasswordAttack.select_wordlists(self)
            return wordlist
    
    def set_path_wordlist(self, path):
        PasswordAttack.pathdirect_wordlist = path

    def get_path_wordlist(self):
        return PasswordAttack.pathdirect_wordlist
                
    def select_wordlists(self):
        # select wordlists
        wordlist = self.dropdown_wordLists.currentText()
        print("wordlist: ", wordlist)

        # check if wordlist is empty
        if wordlist == 'Wordlists':
            wordlist = PasswordAttack.get_path_wordlist(self)
            #return 
        
        # get path of wordlist
        path = Path(f"{os.getcwd}/data/Wordlists/{wordlist}")
        print("path of wordlist: ", path)

        # check if wordlist exists
        if path.exists() != True:
            print(f"File exists at: {path.exists()}")
        print(f"Get file at: {path}")

        # show path of wordlist
        self.lineEdit_inputFileDict.setText(str(path.name))

        return path
    
    def show_loadding(self):
        self.movie = QMovie(f"{os.getcwd}/assets/images/password-attack.gif")
        self.movie.setCacheMode(QMovie.CacheMode.CacheAll)
        self.movie.setSpeed(100)
        self.label_loadding.setMovie(self.movie)
        self.movie.start()

    def select_mode_attack(self):
        mode = self.dropdown_modeAttack.currentText()
        if mode == "Straight forward":
            mode = "0"
        elif mode == "Combinator":
            mode = "1"
        elif mode == "Skipping 1":
            mode = "6"
        elif mode == "Skipping 2":
            mode = "7"
        else:
            mode = None
        
        return mode
    
    def start_attack(self):
        self.textEdit_result_hashcat.clear()

        runner = HashcatRunner()
        runner.finished.connect(lambda: PasswordAttack.on_finished(self))
        runner.update_text.connect(lambda text: PasswordAttack.on_update_text(self, text))

        self.btn_start_attack.setEnabled(False)
        PasswordAttack.show_loadding(self)
        
        password = self.lineEdit_passwordDict.text()
        password_hash = hashlib.md5(password.encode()).hexdigest()
        mode = PasswordAttack.select_mode_attack(self)
        wordlist = PasswordAttack.check_wordlist(self)
        main = self
        thread = threading.Thread(target=runner.run_hashcat, args=(mode, wordlist, password_hash, password, main))
        thread.start()

    def on_finished(self):
        self.btn_start_attack.setEnabled(True)
        print("Finished running hashcat")

    def on_update_text(self, text):
        self.textEdit_result_hashcat.append(text)
        print("update: "+ text)
       
class HashcatRunner(QObject):
    finished = pyqtSignal()
    update_text = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run_hashcat(self, mode, wordlist, hash, password, main):
        
        if mode == 1:
            # Combinator mode cannot use crackstation.txt
            if wordlist.name == "crackstation.txt":
                self.update_text.emit(f"Error: Combinator mode cannot use crackstation.txt")
                return
        elif mode == 6 or mode == 7:
            # Skipping mode cannot use crackstation.txt
            if wordlist.name == "crackstation.txt":
                self.update_text.emit(f"Error: Skipping mode cannot use crackstation.txt")
                return
        else:
            # Straight forward mode can use any wordlist
            pass

        hashcat_exe = "hashcat"

        if mode == "0": # Straight forward
            command = f'{hashcat_exe} -m 0 -a {mode} {hash} {wordlist} | grep "{password}"'
            
        elif mode == "1": # Combination
            command = f'{hashcat_exe} -m 0 -a {mode} {hash} {wordlist} {wordlist} | grep "{password}"'
            
        elif mode == "6": # Skipping 1
            command = f'{hashcat_exe} -m 0 -a {mode} {hash} {wordlist} ?d?d?d?d | grep "{password}"'
        
        elif mode == "7": # Skipping 2
            command = f'{hashcat_exe} -m 0 -a {mode} {hash} ?d?d?d?d {wordlist} | grep "{password}"'
            
        else:
            self.update_text.emit(f"No mode selected")
            return

        print(command)
        if command is None:
            return "No password found"
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in process.stdout:
                # Process the output here
                if password in line:
                    # Password found, do something
                    main.label_focus_output.setText(f"Password found: {password}")
                    main.label_focus_output.setStyleSheet("color: Red;")
                    self.update_text.emit(f"Password found: {password}\nHash: {hash}\nWordlist: {wordlist}\nMode: {mode}\nstatus: cracked\n")
                    break
            process.communicate()

            # Check if the process was successful or not
            if process.returncode == 0:
                #redirect password to history_of_cracked.txt
                try:
                    with open(f"{os.getcwd}/data/history_of_cracked.txt", "a") as file:
                        file.write(f"Password: {password}\n")
                        self.label_focus_output.setText(f"Password found: {password}")
                        self.label_focus_output.setStyleSheet("color: Red;")
                except Exception as e:
                    #self.update_text.emit(f"Error: {str(e)}")
                    print(f"Error: {str(e)}")
                    
                self.finished.emit()
            else:
                #check if password is in the list of history_of_cracked.txt
                try:
                    with open(f"{os.getcwd}/data/history_of_cracked.txt", "r") as file:
                        for line in file:
                            if password in line:
                                # show password found & value that we need
                                main.label_focus_output.setText(f"Password found: {password}")
                                main.label_focus_output.setStyleSheet("color: Red;")
                                self.update_text.emit(f"Password found: {password}\n")
                                break
                            else:
                                self.update_text.emit(f"Password not found: {password}\nHash: {hash}\nWordlist: {wordlist}\nMode: {mode}\nstatus: uncracked\n")
                                main.label_focus_output.setText(f"Password not found: {password}")
                                main.label_focus_output.setStyleSheet("color: Green;")
                                break
                except Exception as e:
                    #self.update_text.emit(f"Error: {str(e)}")
                    print(f"Error: {str(e)}")
            
            if process.returncode == 255:
                print("Hashcat Error: Invalid argument")
                # Additional debug output
                for line in process.stderr:
                    self.update_text.emit(f"Hashcat Error Output: {line}")
            
            if process.returncode == 4294967295:
                print("Hashcat Error: Hashcat is already running")
                self.update_text.emit(f"Error: Hashcat process exited with code {process.returncode}")

        except Exception as e:
            self.update_text.emit(f"Error: {str(e)}")
            main.label_focus_output.setText(f"Password not found: {password}")
            main.label_focus_output.setStyleSheet("color: Green;")