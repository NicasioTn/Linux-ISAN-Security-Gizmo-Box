import subprocess
from PyQt6.QtWidgets import QMainWindow, QListWidgetItem, QApplication
from PyQt6.QtCore import Qt
from PyQt6.uic import loadUi
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QFileInfo
from PyQt6.QtWidgets import QFileDialog

from pathlib import Path
import os
import sys

class MultiselectList(QMainWindow):

    left_list = []
    right_list = []
    
    def __init__(self):
        super().__init__()
        loadUi(f"{os.getcwd()}/assets/ui/multiwordlist.ui", self)
        self.setWindowTitle("Multi-Select Wordlist")
        self.setWindowIcon(QIcon(f"{os.getcwd()}/assets/icons/icon_gixmobox.png"))

        self.btn_toRight.clicked.connect(self.transfer_to_right)
        self.btn_toLeft.clicked.connect(self.transfer_to_left)

        self.populate_left_list()
        #self.listWidget_left.itemSelectionChanged.connect(self.print_left_list)
        #self.listWidget_right.itemSelectionChanged.connect(self.print_right_list)

        #self.btn_ok.clicked.connect(lambda: self.get_list_items(self.listWidget_right))

        self.btn_add.clicked.connect(self.open_file_wordlist)
        self.btn_remove.clicked.connect(self.remove_file)

    def populate_left_list(self):
        folder_path = os.getcwd() + "/data/Wordlists/"
        file_list = os.listdir(folder_path)

        for file in file_list:
            item = QListWidgetItem(file)
            self.listWidget_left.addItem(item)

    def transfer_to_right(self):
        selected_items = self.listWidget_left.selectedItems()
        for item in selected_items:
            self.listWidget_left.takeItem(self.listWidget_left.row(item))
            self.listWidget_right.addItem(item)

    def transfer_to_left(self):
        selected_items = self.listWidget_right.selectedItems()
        for item in selected_items:
            self.listWidget_right.takeItem(self.listWidget_right.row(item))
            self.listWidget_left.addItem(item)

    def print_left_list(self):
        for i in range(self.listWidget_left.count()):
            print(self.listWidget_left.item(i).text())

    def print_right_list(self):
        for i in range(self.listWidget_right.count()):
            print(self.listWidget_right.item(i).text())

    def get_list_items(self, list_widget):
        for i in range(list_widget.count()):
            self.right_list.append(list_widget.item(i).text())
        self.close()

    def get_left_list(self):
        return self.left_list
    
    def get_right_list(self):
        return self.right_list
    
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
                # copy file to data/Wordlists folder
                copy = subprocess.run(['cp', filepath, os.getcwd() + "/data/Wordlists/"])

                # add file to listWidget_left
                item = QListWidgetItem(file_name)
                self.listWidget_left.addItem(item)

                if copy == 0:
                    print("File copied successfully")
                else:
                    print("File copy failed")

                if path.exists() != True: # check if file exists 
                    print(f"File exists at: {path.exists()}")
                    
                print(f"Get file at: {path}")                 

        return filepath
    
    def remove_file(self):
        default_wordlist = "rockyou.txt"

        # remove file from data/Wordlists folder and listWidget_left
        selected_items = self.listWidget_left.selectedItems()
        for item in selected_items:
            if item.text() == default_wordlist:
                print(f"Cannot remove default wordlist: {default_wordlist}")
                continue
            
            self.listWidget_left.takeItem(self.listWidget_left.row(item))
            os.remove(os.getcwd() + "/data/Wordlists/" + item.text())
            print(f"File removed: {item.text()}")

        
