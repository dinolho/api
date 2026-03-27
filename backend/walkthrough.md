# Personal Finance Dashboard Walkthrough

The Personal Finance Dashboard is now complete! It provides a comprehensive solution for tracking expenses, bank balances, investments, and crypto holdings with a premium dark-mode interface.

## Key Features

- **Multi-Bank Dashboard**: Visualize total balance, monthly expenses, and investment growth at a glance.
- **Bank Statement Integration**: Import CSV files from your banks to automatically sync transactions and update balances.
- **Manual Control**: Add transactions manually when needed.
- **Investment & Crypto Tracking**: Dedicated sections for monitoring your portfolio performance.
- **Premium Design**: Modern, responsive dark-mode UI with glassmorphism and interactive charts.

## Implementation Details

### Backend (Python/Flask)
- [app.py](file:///opt/code/dev/etc/finances/app.py): REST API for managing accounts, transactions, and investments.
- [database.py](file:///opt/code/dev/etc/finances/database.py): SQLite schema with tables for optimized financial data storage.
- [parsers.py](file:///opt/code/dev/etc/finances/parsers.py): Intelligent CSV parser that maps common bank statement headers.
- [seed.py](file:///opt/code/dev/etc/finances/seed.py): Utility to populate the database with initial sample data.

### Frontend (HTML/CSS/JS)
- [index.html](file:///opt/code/dev/etc/finances/templates/index.html): Main dashboard structure with a collapsible sidebar.
- [style.css](file:///opt/code/dev/etc/finances/static/css/style.css): Custom premium dark theme with vibrant accents.
- [dashboard.js](file:///opt/code/dev/etc/finances/static/js/dashboard.js): Interactive logic using Chart.js for beautiful data visualization.

## How to Run

1. **Install Dependencies**:
   ```bash
   pip install flask
   ```
2. **Initialize & Seed Data**:
   ```bash
   python3 seed.py
   ```
3. **Start the Application**:
   ```bash
   python3 app.py
   ```
4. **Access the Dashboard**:
   Open your browser at `http://localhost:5000`

## Verification Results

- [x] **Database Schema**: Successfully created tables for accounts, transactions, and investments.
- [x] **API Endpoints**: CRUD operations for transactions and accounts verified.
- [x] **CSV Parser**: Tested with sample bank statement data (DD/MM/YYYY and YYYY-MM-DD formats).
- [x] **UI/UX**: Responsive layout and chart rendering confirmed.

> [!TIP]
> To import your bank statements, click the "Importar Extrato" button on the dashboard and select your CSV file. The system will automatically map the columns!

![Dashboard Overview](file:///opt/code/dev/etc/finances/screenshot_placeholder.png)
*(Note: Use your browser to view the actual dashboard at http://localhost:5000)*
