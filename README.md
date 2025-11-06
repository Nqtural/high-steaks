# High Steaks
A Flask web app where users register, log in, and gamble virtual currency on Rock–Paper–Scissors with live stats, auto-betting, and an admin panel for managing users and balances.

## Features
- User registration and login with password hashing and CSRF protection.
- Rock–Paper–Scissors betting with balance, profit, and W/D/L tracking.​
- Auto mode with configurable win/loss wager multipliers.​
- Account page to reset stats and change password (with identity checks).​
- Admin panel to edit users (username, email, admin flag, balance) and delete accounts.​

## Tech stack
- Flask, Flask-Login, Flask-WTF, SQLAlchemy.​
- Jinja2 templates and vanilla JS/CSS frontend.​
- SQLite by default; configurable via DATABASE_URL.​

## Getting started
## Requirements
- Python 3​

## Environment variables
- SECRET_KEY: Flask secret key.​
- DATABASE_URL: SQLAlchemy URL; defaults to sqlite:///app.db.​
- ADMIN_USERNAME: Initial admin username; required on first boot if no admin exists.​
- ADMIN_EMAIL: Initial admin email; required on first boot if no admin exists.​
- ADMIN_PASSWORD: Initial admin password; required on first boot if no admin exists.​

Note: On first run, the app creates tables and bootstraps the first admin from the above variables; if any required admin variable is empty or missing, the app prints a message and exits.​

## Install and run (development)
- Set environment variables (at least SECRET_KEY and the ADMIN_* trio for first boot).​
- Install dependencies `bin/pip install -r requirements.txt`
- Run the app: `bin/flask --app main run --host=0.0.0.0 --port=8443 --cert=adhoc`

Default config enables CSRF; session cookies are HttpOnly+Lax, and Secure can be enabled for HTTPS.​
## License
Licensed under AGPL-3, see <a href="./LICENSE">LICENSE</a>​