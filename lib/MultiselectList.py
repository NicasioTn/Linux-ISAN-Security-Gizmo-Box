from PyQt6.QtWidgets import QMainWindow, QListWidgetItem, QApplication
from PyQt6.QtCore import Qt
from PyQt6.uic import loadUi
from PyQt6.QtGui import QIcon

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