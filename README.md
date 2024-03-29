# <img src="https://user-images.githubusercontent.com/55986701/279825177-3e0afcf1-afad-4248-b111-a97540bcf6da.png" width="40"/> ISAN Security Gizmo Box for Linux 
<div id="header" align="center">
  <img src="https://user-images.githubusercontent.com/55986701/279823230-7a53ef1c-e4d3-4385-bdae-f280228ec190.png" width="700"/>
</div>

## Description 👀📋
ISAN Security Gizmo Box เป็นเครื่องมือที่รวบรวมเครื่องมือเกี่ยวกับการตรวจสอบความมั่นคงปลอดภัยเบื้องต้นโดยแบ่งประเภทผู้ใช้งานงานออกเป็น 2 ประเภท ได้แก่ Advanced User ประกอบด้วยเครื่องมือ Password Evaluation, Malware Scanning, Message Digest Generator และ Network Engineer ประกอบด้วยเครื่องมือ Vulnerability Scanning, HTTPS Testing ไว้ในเครื่องมือเดียวกันและอยู่ในรูปแบบของ Graphical User Interface (GUI) ที่พัฒนาด้วย Qt Designer และเรียกใช้งานด้วยภาษา Python อีกทั้งยังนำเสนอในรูปแบบ Virtual Appliance ของ 2 Virtual Machines คือ Oracle VM VirtualBox และ VMware Workstation Player  <br>

## How to Install and Run The Project 📁🗂️
<div id="header" align="center">
  <p>On Desktop right click -> select open-terminal -> This path would be [~/Desktop] </p>
  <img src="https://user-images.githubusercontent.com/55986701/279825981-fc10a060-e883-4d67-961a-5ed18b3d6e82.png" width="700"/>
</div>

### 1. Git clone Repo 🚀
```
git clone https://github.com/NicasioTn/Linux-ISAN-Security-Gizmo-Box.git
```
### 2. Setup Program 📦
```
python3 Linux-ISAN-Security-Gizmo-Box/setup.py
```
<div>
  <p>❗If the install packet requires a password you should type "kali" on prompt and press enter</p>
  <p>❗don't forget to check the linking path of the file in the source code [if the program is not running] </p>
</div>

## How to Use the Project🔌
### Oracle Virtual Box
<div id="header" align="center">
  <p> file -> import appliance -> choose your location .ova </p>
  <img src="https://user-images.githubusercontent.com/55986701/279824078-f51d1ea7-31d5-4fd3-b876-83580970e46f.png" width="700"/>
  <p> start -> execute GizmoBox ✅</p>
  <img src="https://user-images.githubusercontent.com/55986701/279823946-8f79f0d1-2cab-48c1-95a3-0810e0063547.png" width="700"/>
</div>

### VMware Workstation
<div id="header" align="center">
  <p> file -> open -> choose your location .ovf </p>
  <img src="https://user-images.githubusercontent.com/55986701/279824325-a20cbff7-f551-4b46-8d6d-44e386a951f0.png" width="700"/>
  <p> start -> execute GizmoBox ✅</p>
  <img src="https://user-images.githubusercontent.com/55986701/279824240-b9b6c5bd-7be6-4a56-9b96-99eb02f8fcfb.png" width="700"/>
</div>

## Author
* Kanjana Pinit (กาญจนา พินิจ)
* Peeratach Butto (พีรธัช บุตรโท)
* Faculty of Informatics (คณะวิทยาการสารสนเทศ)
* Department of Computer Science (สาขาวิทยาการคอมพิวเตอร์)
* Mahasarakham University (มหาวิทยาลัยมหาสารคาม)

## License 📝🧑‍⚖️
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
Copyright (c) 2023 NicasioTn <br>
For more information, please visit the author's website: https://github.com/NicasioTn
