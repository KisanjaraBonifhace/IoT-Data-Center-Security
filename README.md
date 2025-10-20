# IoT-Data-Center-Security
IoT &amp; PHP/MySQL system to monitor data centers and secure operations.
# IoT Technology for Improving Data Center Security in Tanzanian Banks

## Project Overview
This project is an IoT-based system designed to **enhance security in data centers** of Tanzanian banks. It monitors **temperature fluctuations** and detects **unauthorized access**, ensuring proactive responses to potential threats. Alerts are sent via **Telegram and Pushover**, while data is stored for analysis and reporting.

## Features
- **Temperature Monitoring**
  - Simulated real-time temperature readings.
  - Alerts when temperatures exceed safe limits (Warning & Critical levels).
  - Integration with RabbitMQ for data transmission.
- **Unauthorized Access Detection**
  - Monitors failed login attempts.
  - Sends alerts for suspicious activities.
- **Dashboard & Reporting**
  - Web interface displaying live readings and historical data.
  - Downloadable reports (PDF/CSV) for admin review.
  - Secure login for admins.
- **Notifications**
  - Real-time alerts via **Telegram Bot** and **Pushover**.

## Tech Stack
- **Backend:** Python (Flask)
- **Frontend:** HTML, CSS, Bootstrap 5
- **Database:** SQLite/MySQL
- **Messaging:** RabbitMQ
- **Notifications:** Telegram Bot, Pushover
- **Virtual Environment:** Raspbian VM (for IoT simulation) & Kali Linux (server)


