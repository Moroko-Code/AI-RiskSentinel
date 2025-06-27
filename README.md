# 🤖 AI-RiskSentinel
**An AI-Driven Cybersecurity Risk Assessment System**  
Built with Flask · MongoDB · Nmap · MFA · Email Alerts

---

## 📌 Overview

AI-RiskSentinel is a cybersecurity tool that leverages artificial intelligence and network scanning to detect, assess, and respond to threats in a connected system. Designed with Flask and MongoDB, it integrates real-time scanning, MFA for access control, and automated email alerts to keep your network safe.

---

## 🚀 Features

- 🔍 **Network Scanning with Nmap**  
  Automatically identifies open ports and potential vulnerabilities.

- 🧠 **AI-Based Risk Classification**  
  Dynamically categorizes risks using qualitative analysis techniques.

- 🔐 **Multi-Factor Authentication (MFA)**  
  Adds an extra layer of protection for accessing the system.

- 📧 **Automated Email Alerts**  
  Sends notifications based on threat severity to system admins.

- 💾 **MongoDB Storage**  
  Stores scan results, logs, and user data for future reference.

---

## 🛠️ Tech Stack

| Tool       | Purpose                        |
|------------|--------------------------------|
| Flask      | Backend web application        |
| MongoDB    | Database for persistent storage|
| Nmap       | Network vulnerability scanner  |
| Python     | Core logic and automation      |
| SMTP       | Email alert service            |

---

## 📷 Screenshots 
![image](https://github.com/user-attachments/assets/973f2dfa-bda4-4c0f-a7ca-7450b7dc9173)
![image](https://github.com/user-attachments/assets/072951bc-d9da-4dd1-9f4e-101d168a1c06)
![image](https://github.com/user-attachments/assets/24228596-2b10-46ba-96c6-7ecdf07b1e9a)
![image](https://github.com/user-attachments/assets/f025194c-71ef-40f4-bd9d-e1af64b54f14)
![image](https://github.com/user-attachments/assets/048c3f92-73ad-4511-a653-01f1482540d1)
![image](https://github.com/user-attachments/assets/0d1a3ec3-e134-437a-9c9b-35cab723a7cd)

---

## 🧪 How to Run

# Clone the repository
git clone https://github.com/Moroko-Code/AI-RiskSentinel.git
cd AI-RiskSentinel

# (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Start the application
python main.py
terminal: flask run

---

## ⚙️ Configuration

Create a 'config.py' file in the root directory with the following:
---.env
SECRET_KEY = ('SECRET_KEY')  
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = your_port
MAIL_USE_TLS = ""
MAIL_DEFAULT_SENDER = your_emailSender@example.com
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_password
MONGO_URI=mongodb://localhost:27017/RISK

---

## 📬 Contact

Made by **Moroko-Code**  
GitHub: [@Moroko-Code](https://github.com/Moroko-Code)

---

## ✅ Future Enhancements

- Implement role-based user management
- Integrate live dashboards with charts
- Add threat prediction using machine learning
- Deploy on cloud for scalability
