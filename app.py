from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from datetime import datetime, timedelta
import json
import os
import math
import secrets
import hmac
import re
from urllib.parse import urlsplit
from flask import abort, render_template_string
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# SECRET_KEY should be set in the environment in production.
# The random fallback keeps local development working but logs everyone out on restart.
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# Hosted MySQL-compatible databases (e.g. TiDB Cloud) require TLS. If no CA
# bundle was configured through the environment, fall back to common system
# locations so hosted runtimes (Render, Vercel, ...) work out of the box.
if not os.environ.get("DB_SSL_CA"):
    for _ca_candidate in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(_ca_candidate):
            os.environ["DB_SSL_CA"] = _ca_candidate
            break

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'profile_pics')
# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=bool(os.environ.get('VERCEL') or os.environ.get('RENDER')))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# System Settings (Feature in program instead of DB)
LOW_STOCK_THRESHOLD = 10

def get_db_connection():
    # Database settings come from environment variables so no credentials live in code.
    # Defaults match a local MySQL setup; set DB_HOST, DB_PORT, DB_USER, DB_PASSWORD
    # and DB_NAME for any hosted deployment.
    args = dict(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "LOGIN_1"),
        connection_timeout=int(os.environ.get("DB_CONNECT_TIMEOUT", "10")),
    )
    # Hosted MySQL-compatible databases (e.g. TiDB Cloud) usually require TLS.
    # Point DB_SSL_CA at a CA bundle, e.g. /etc/ssl/certs/ca-certificates.crt on Linux.
    if os.environ.get("DB_SSL_CA"):
        args["ssl_ca"] = os.environ["DB_SSL_CA"]
        args["ssl_verify_cert"] = os.environ.get("DB_SSL_VERIFY", "1") == "1"
    # The pure-Python connector avoids missing-plugin errors (mysql_native_password)
    # that the C extension hits against some hosted MySQL-compatible databases.
    if os.environ.get("DB_USE_PURE", "1") == "1":
        args["use_pure"] = True
    return mysql.connector.connect(**args)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def valid_quantity(value, allow_zero=False):
    if isinstance(value, bool) or not str(value).isdigit():
        raise ValueError("Invalid quantity")
    result = int(value)
    if result < (0 if allow_zero else 1) or result > 1_000_000:
        raise ValueError("Invalid quantity")
    return result


def valid_price(value):
    result = float(value)
    if not math.isfinite(result) or result < 0 or result > 1_000_000_000:
        raise ValueError("Invalid price")
    return result


@app.before_request
def protect_writes():
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not hmac.compare_digest(request.form.get("csrf_token", ""), session["csrf_token"]):
            abort(403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)
        origin = request.headers.get("Origin")
        if origin and urlsplit(origin).netloc != request.host:
            abort(403)
    if request.endpoint in {"delete_medicine", "delete_supplier", "clear_sales"}:
        if "username" not in session:
            return redirect(url_for("login"))
        token = session["csrf_token"]
        if request.method == "GET":
            return render_template_string(
                '<h1>Confirm deletion</h1><p>This cannot be undone.</p>'
                '<form method="post">'
                '<button type="submit">Confirm deletion</button></form>', token=token)
        if not hmac.compare_digest(request.form.get("csrf_token", ""), token):
            abort(403)


@app.after_request
def security_headers(response):
    # Add the session token to server-rendered forms, including modal forms.
    # No JavaScript or template changes are required for existing screens.
    if response.mimetype == "text/html":
        token = session.get("csrf_token", "")
        html = response.get_data(as_text=True)
        html = re.sub(r"(<form\b[^>]*>)", lambda m: m.group(1) +
                      '<input type="hidden" name="csrf_token" value="' + token + '">',
                      html, flags=re.IGNORECASE)
        response.set_data(html)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


# Global context processor to provide alert counts and user details to all templates
@app.context_processor
def inject_global_data():
    if "username" in session:
        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)
            today = datetime.now().date()
            
            # Expiry Alerts
            expiry_threshold = today + timedelta(days=10)
            cursor.execute("SELECT COUNT(*) as count FROM medicine WHERE EXPIRY_DATE <= %s", (expiry_threshold,))
            alert_count = cursor.fetchone()['count']
            
            # Low Stock Alerts (Aggregated by Name)
            cursor.execute("""
                SELECT MEDICINE_NAME, SUM(STOCK_QUANTITY) as total_stock 
                FROM medicine 
                GROUP BY MEDICINE_NAME 
                HAVING total_stock <= %s
            """, (LOW_STOCK_THRESHOLD,))
            low_stock_items = cursor.fetchall()
            low_stock_count = len(low_stock_items)
            
            # Current User Info
            cursor.execute("SELECT * FROM users WHERE USERNAME=%s", (session["username"],))
            user = cursor.fetchone()
            
            cursor.close()
            db.close()
            return dict(alert_count=alert_count, low_stock_count=low_stock_count, low_stock_items=low_stock_items, low_stock_threshold=LOW_STOCK_THRESHOLD, current_user=user)
        except Exception as e:
            print(f"Context Processor Error: {e}")
            return dict(alert_count=0, low_stock_count=0, low_stock_items=[], low_stock_threshold=LOW_STOCK_THRESHOLD, current_user=None)
    return dict(alert_count=0, low_stock_count=0, low_stock_items=[], low_stock_threshold=LOW_STOCK_THRESHOLD, current_user=None)

# --- ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    # This is one shared pharmacy, not a separate workspace per signup.
    # Hosted registration must be deliberately enabled by the operator.
    if (os.environ.get("VERCEL") or os.environ.get("RENDER")) and os.environ.get("ALLOW_PUBLIC_REGISTRATION") != "1":
        return "Public registration is disabled for this shared pharmacy demo.", 403
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        
        # Security: Hash Password
        hashed_password = generate_password_hash(password)
        
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (USERNAME, EMAIL, PASSWORD) VALUES (%s, %s, %s)", (username, email, hashed_password))
            db.commit()
            cursor.close()
            db.close()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "error")
            return redirect(url_for("register"))
            
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE USERNAME=%s", (username,))
        user = cursor.fetchone()
        
        if user:
            # Check hashed password
            if user["PASSWORD"].startswith("scrypt:") or user["PASSWORD"].startswith("pbkdf2:"):
                is_valid = check_password_hash(user["PASSWORD"], password)
            else:
                # Fallback for plain text transition
                is_valid = (user["PASSWORD"] == password)
                if is_valid:
                    hashed_pw = generate_password_hash(password)
                    cursor.execute("UPDATE users SET PASSWORD=%s WHERE USERNAME=%s", (hashed_pw, username))
                    db.commit()
            
            if is_valid:
                session.clear()
                session["username"] = username
                cursor.close()
                db.close()
                return redirect(url_for("dashboard"))
        
        cursor.close()
        db.close()
        flash("Invalid credentials", "error")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    # Knowing a username/email is not proof of account ownership.
    # Re-enable only after an expiring, single-use verified-email flow exists.
    return "Password reset is unavailable. Contact the project owner for account recovery.", 403

@app.route("/dashboard")
def dashboard():
    if "username" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

# --- MEDICINE MODULE ---

@app.route("/get_medicine_details/<name>")
def get_medicine_details(name):
    if "username" not in session: return jsonify({"error": "Unauthorized"}), 401
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Check if exists
    cursor.execute("SELECT MEDICINE_ID, CATEGORY, PRICE, PURCHASE_PRICE FROM medicine WHERE LOWER(MEDICINE_NAME) = LOWER(%s) LIMIT 1", (name,))
    details = cursor.fetchone()
    
    if details:
        cursor.close()
        db.close()
        return jsonify(details)
    else:
        # Suggest new ID if not found
        cursor.execute("SELECT MEDICINE_ID FROM medicine WHERE MEDICINE_ID REGEXP '^M[0-9]+$' ORDER BY CAST(SUBSTRING(MEDICINE_ID, 2) AS UNSIGNED) DESC LIMIT 1")
        last_id_row = cursor.fetchone()
        if last_id_row:
            last_num = int(last_id_row['MEDICINE_ID'][1:])
            new_id = f"M{(last_num + 1):03d}"
        else:
            new_id = "M001"
        
        cursor.close()
        db.close()
        return jsonify({"MEDICINE_ID": new_id, "is_new": True})

@app.route("/medicine")
def medicine():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.*, s.medicines_supplied 
        FROM medicine m 
        LEFT JOIN suppliers s ON m.SUPPLIER_NAME = s.supplier_name
    """)
    medicines = cursor.fetchall()
    
    cursor.execute("SELECT supplier_name, medicines_supplied FROM suppliers")
    suppliers = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template("medicine.html", medicines=medicines, suppliers=suppliers)

@app.route("/add_medicine", methods=["POST"])
def add_medicine():
    if "username" not in session: return redirect(url_for("login"))
    name = request.form["name"].strip()
    batch = request.form["batch"]
    cat = request.form["category"]
    price = request.form["price"]
    purchase_price_str = request.form.get("purchase_price", "0")
    purchase_price = purchase_price_str or "0"
    exp = request.form["expiry"]
    stock = request.form["stock"]
    pur_date = request.form["purchase_date"]
    supplier_name = request.form.get("supplier_name")
    
    try:
        price = valid_price(price)
        purchase_price = valid_price(purchase_price)
        stock = valid_quantity(stock, allow_zero=True)
    except (ValueError, TypeError):
        flash("Prices and stock must be valid non-negative numbers.", "error")
        return redirect(url_for("medicine"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # 1. Fully Automatic ID Management
        # Always check if this medicine name already exists to reuse the ID
        cursor.execute("SELECT MEDICINE_ID, CATEGORY FROM medicine WHERE LOWER(MEDICINE_NAME) = LOWER(%s) LIMIT 1", (name,))
        existing = cursor.fetchone()
        
        if existing:
            m_id = existing['MEDICINE_ID']
            # Optionally reuse category if not provided or to keep consistency
            if not cat: cat = existing['CATEGORY']
        else:
            # Generate a new unique ID: Find the current highest number in MED-xxx
            cursor.execute("SELECT MEDICINE_ID FROM medicine WHERE MEDICINE_ID LIKE 'MED-%%' OR MEDICINE_ID REGEXP '^M[0-9]+$'")
            all_ids = cursor.fetchall()
            max_num = 0
            for row in all_ids:
                try:
                    # Handle both MED-xxx and Mxxx formats
                    id_str = row['MEDICINE_ID']
                    if '-' in id_str:
                        num = int(id_str.split('-')[1])
                    else:
                        num = int(id_str[1:])
                    if num > max_num: max_num = num
                except:
                    continue
            m_id = f"M{(max_num + 1):03d}"

        cursor.execute("INSERT INTO medicine (MEDICINE_ID, MEDICINE_NAME, BATCH_NO, CATEGORY, EXPIRY_DATE, PRICE, PURCHASE_PRICE, STOCK_QUANTITY, PURCHASE_DATE, SUPPLIER_NAME) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                       (m_id, name, batch, cat, exp, price, purchase_price, stock, pur_date, supplier_name))

        # Automatically record this as the initial purchase
        new_med_id = cursor.lastrowid
        if int(stock) > 0:
            total_cost = int(stock) * float(purchase_price)
            cursor.execute("INSERT INTO purchases (med_id, supplier_name, quantity, unit_price, total_cost) VALUES (%s, %s, %s, %s, %s)",
                           (new_med_id, supplier_name, stock, purchase_price, total_cost))

        db.commit()
        flash(f"Medicine {name} added (ID: {m_id})!", "success")
    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Database error: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("medicine"))

@app.route("/update_medicine/<id>", methods=["POST"])
def update_medicine(id):
    if "username" not in session: return redirect(url_for("login"))
    name = request.form["name"].strip()
    m_id = request.form.get("id", "").strip()
    batch = request.form["batch"]
    cat = request.form["category"]
    price = request.form["price"]
    purchase_price_str = request.form.get("purchase_price", "0")
    purchase_price = purchase_price_str or "0"
    exp = request.form["expiry"]
    stock = request.form["stock"]
    pur_date = request.form["purchase_date"]
    supplier_name = request.form.get("supplier_name")
    
    try:
        price = valid_price(price)
        purchase_price = valid_price(purchase_price)
        stock = valid_quantity(stock, allow_zero=True)
    except (ValueError, TypeError):
        flash("Prices and stock must be valid non-negative numbers.", "error")
        return redirect(url_for("medicine"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        # Check if ID/Category should be synced for all records with this name
        cursor.execute("SELECT MEDICINE_ID, CATEGORY FROM medicine WHERE LOWER(MEDICINE_NAME) = LOWER(%s) AND id != %s LIMIT 1", (name, id))
        other_batch = cursor.fetchone()
        
        if other_batch:
            # If name matches another medicine, force its ID and Category to be consistent
            m_id = other_batch['MEDICINE_ID']
            cat = other_batch['CATEGORY']

        # Update the current record
        cursor.execute("""
            UPDATE medicine 
            SET MEDICINE_NAME=%s, MEDICINE_ID=%s, BATCH_NO=%s, CATEGORY=%s, EXPIRY_DATE=%s, PRICE=%s, 
                PURCHASE_PRICE=%s, STOCK_QUANTITY=%s, PURCHASE_DATE=%s, SUPPLIER_NAME=%s 
            WHERE id=%s
        """, (name, m_id, batch, cat, exp, price, purchase_price, stock, pur_date, supplier_name, id))
        
        # Propagation: If the user changed the name or category or ID, update ALL other batches of this same medicine
        cursor.execute("UPDATE medicine SET MEDICINE_ID=%s, CATEGORY=%s WHERE LOWER(MEDICINE_NAME) = LOWER(%s)", (m_id, cat, name))
        
        db.commit()
        flash(f"Medicine {name} updated and synced across batches!", "success")
    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Error updating medicine: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("medicine"))

@app.route("/delete_medicine/<id>", methods=["GET", "POST"])
def delete_medicine(id):
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM medicine WHERE id=%s", (id,))
        db.commit()
        flash("Medicine removed from inventory.", "success")
    except mysql.connector.Error as err:
        flash(f"Cannot delete medicine: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("medicine"))

# --- PURCHASE MODULE ---

@app.route("/purchase")
def purchase():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, m.MEDICINE_NAME 
        FROM purchases p 
        JOIN medicine m ON p.med_id = m.id 
        ORDER BY p.purchase_date DESC
    """)
    purchases = cursor.fetchall()
    
    cursor.execute("SELECT id, MEDICINE_NAME, STOCK_QUANTITY, SUPPLIER_NAME, PRICE FROM medicine")
    medicines = cursor.fetchall()
    
    low_stock_items = [m for m in medicines if m['STOCK_QUANTITY'] <= LOW_STOCK_THRESHOLD]
    
    cursor.close()
    db.close()
    return render_template("purchase.html", purchases=purchases, medicines=medicines, low_stock_items=low_stock_items)

@app.route("/add_purchase", methods=["POST"])
def add_purchase():
    if "username" not in session: return redirect(url_for("login"))
    med_id = request.form.get("med_id")
    supplier_name = request.form.get("supplier_name")
    try:
        quantity = valid_quantity(request.form.get("quantity", 0))
        unit_price = valid_price(request.form.get("unit_price", 0))
    except ValueError:
        flash("Invalid quantity or unit price.", "error")
        return redirect(url_for("purchase"))
    total_cost = quantity * unit_price
    
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO purchases (med_id, supplier_name, quantity, unit_price, total_cost) VALUES (%s, %s, %s, %s, %s)",
                       (med_id, supplier_name, quantity, unit_price, total_cost))
        db.commit()
        flash("Purchase recorded!", "success")
    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Database error: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("purchase"))

# --- BILLING MODULE ---

@app.route("/billing")
def billing():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, MEDICINE_NAME, PRICE, STOCK_QUANTITY, BATCH_NO FROM medicine WHERE STOCK_QUANTITY > 0")
    medicines = cursor.fetchall()
    cursor.execute("SELECT * FROM sales ORDER BY SALE_DATE DESC LIMIT 10")
    recent_sales = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("billing.html", medicines=medicines, recent_sales=recent_sales)

@app.route("/process_sale", methods=["POST"])
def process_sale():
    if "username" not in session: return redirect(url_for("login"))
    cart_data = request.form.get("cart_json")
    customer_name = request.form.get("customer_name")
    if not cart_data or not customer_name:
        flash("Cart is empty or customer name missing!", "error")
        return redirect(url_for("billing"))
    try:
        cart = json.loads(cart_data)
        if not isinstance(cart, list) or not cart or len(cart) > 100:
            raise ValueError("Invalid cart")
        for item in cart:
            if not isinstance(item, dict):
                raise ValueError("Invalid item")
            item['id'] = valid_quantity(item.get('id'))
            item['qty'] = valid_quantity(item.get('qty'))
    except (ValueError, TypeError):
        flash("Invalid cart. Use positive whole quantities.", "error")
        return redirect(url_for("billing"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    invoice_no = datetime.now().strftime("INV-%Y%m%d%H%M%S-") + secrets.token_hex(4)
    total_bill = 0
    try:
        for item in cart:
            med_id = item['id']
            quantity = int(item['qty'])
            cursor.execute("SELECT MEDICINE_NAME, PRICE, PURCHASE_PRICE, STOCK_QUANTITY FROM medicine WHERE id = %s FOR UPDATE", (med_id,))
            medicine = cursor.fetchone()
            if medicine and medicine['STOCK_QUANTITY'] >= quantity:
                item_total = float(medicine['PRICE']) * quantity
                # Calculate Profit: (Selling Price - Purchase Price) * Quantity
                cost_price = float(medicine['PURCHASE_PRICE']) if medicine['PURCHASE_PRICE'] else 0
                item_profit = (float(medicine['PRICE']) - cost_price) * quantity
                
                total_bill += item_total
                new_stock = medicine['STOCK_QUANTITY'] - quantity
                cursor.execute("UPDATE medicine SET STOCK_QUANTITY = %s WHERE id = %s", (new_stock, med_id))
                # id is auto-increment, SALE_DATE defaults to CURRENT_TIMESTAMP in schema, 
                # but we'll be explicit for clarity.
                cursor.execute("INSERT INTO sales (MED_ID, MEDICINE_NAME, QUANTITY, TOTAL_PRICE, PROFIT, CUSTOMER_NAME, INVOICE_NO, SALE_DATE) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                               (med_id, medicine['MEDICINE_NAME'], quantity, item_total, item_profit, customer_name, invoice_no, datetime.now()))
            else:
                raise Exception(f"Insufficient stock for {medicine['MEDICINE_NAME'] if medicine else 'Unknown Item'}")
        db.commit()
        flash(f"Invoice {invoice_no} generated! Total: ₹{total_bill:.2f}", "success")
    except Exception as e:
        db.rollback()
        flash(str(e), "error")
    cursor.close()
    db.close()
    return redirect(url_for("billing"))

@app.route("/clear_sales", methods=["GET", "POST"])
def clear_sales():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM sales")
        db.commit()
        flash("Sales history cleared successfully.", "success")
    except mysql.connector.Error as err:
        flash(f"Error clearing sales: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("billing"))

# --- EXPIRY MODULE ---

@app.route("/expiry")
def expiry():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    # Get all medicines with their pre-calculated DAYS_LEFT from the View
    cursor.execute("SELECT * FROM expiry_tracking ORDER BY DAYS_LEFT ASC")
    medicines = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("expiry.html", medicines=medicines)

# --- SUPPLIER MODULE ---

@app.route("/supplier")
def supplier():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM suppliers")
    suppliers = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("supplier.html", suppliers=suppliers)

@app.route("/add_supplier", methods=["POST"])
def add_supplier():
    if "username" not in session: return redirect(url_for("login"))
    name = request.form.get("name")
    contact_person = request.form.get("contact_person")
    contact_number = request.form.get("contact_number")
    email = request.form.get("email")
    address = request.form.get("address")
    medicines = request.form.get("medicines")
    
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO suppliers (supplier_name, contact_person, contact_number, email, address, medicines_supplied) VALUES (%s, %s, %s, %s, %s, %s)",
                       (name, contact_person, contact_number, email, address, medicines))
        db.commit()
        flash("Supplier added successfully!", "success")
    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Database error: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("supplier"))

@app.route("/update_supplier/<id>", methods=["POST"])
def update_supplier(id):
    if "username" not in session: return redirect(url_for("login"))
    name = request.form.get("name")
    contact_person = request.form.get("contact_person")
    contact_number = request.form.get("contact_number")
    email = request.form.get("email")
    address = request.form.get("address")
    medicines = request.form.get("medicines")
    
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE suppliers SET supplier_name=%s, contact_person=%s, contact_number=%s, email=%s, address=%s, medicines_supplied=%s WHERE id=%s",
                       (name, contact_person, contact_number, email, address, medicines, id))
        db.commit()
        flash("Supplier updated successfully!", "success")
    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Database error: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("supplier"))

@app.route("/delete_supplier/<id>", methods=["GET", "POST"])
def delete_supplier(id):
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM suppliers WHERE id=%s", (id,))
        db.commit()
        flash("Supplier deleted!", "success")
    except mysql.connector.Error as err:
        flash(f"Cannot delete supplier: {err}", "error")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("supplier"))

# --- REPORTS MODULE ---

@app.route("/reports")
def reports():
    if "username" not in session: return redirect(url_for("login"))
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Sales Summary
    cursor.execute("SELECT SUM(TOTAL_PRICE) as total_sales, SUM(PROFIT) as total_profit FROM sales")
    summary = cursor.fetchone()
    
    # Sales by Day (Last 7 Days)
    cursor.execute("""
        SELECT DATE(SALE_DATE) as date, SUM(TOTAL_PRICE) as sales, SUM(PROFIT) as profit
        FROM sales 
        WHERE SALE_DATE >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(SALE_DATE)
        ORDER BY date ASC
    """)
    daily_sales = cursor.fetchall()
    
    # Top Selling Medicines
    cursor.execute("""
        SELECT MEDICINE_NAME, SUM(QUANTITY) as total_qty
        FROM sales
        GROUP BY MEDICINE_NAME
        ORDER BY total_qty DESC
        LIMIT 5
    """)
    top_medicines = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template("reports.html", summary=summary, daily_sales=daily_sales, top_medicines=top_medicines)

# --- SETTINGS MODULE ---

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if "username" not in session: return redirect(url_for("login"))
    global LOW_STOCK_THRESHOLD
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    if request.method == "POST":
        new_username = request.form.get("full_name")
        new_email = request.form.get("email")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        new_threshold = request.form.get("low_stock_threshold")
        
        # Update Threshold
        if new_threshold:
            LOW_STOCK_THRESHOLD = int(new_threshold)
            flash("System preferences updated!", "success")

        # Profile Picture Upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                signature = file.stream.read(16)
                file.stream.seek(0)
                if not (signature.startswith(b"\x89PNG\r\n\x1a\n") or signature.startswith(b"\xff\xd8\xff") or signature.startswith((b"GIF87a", b"GIF89a"))):
                    cursor.close()
                    db.close()
                    flash("Choose a real PNG, JPEG or GIF image.", "error")
                    return redirect(url_for("settings"))
                filename = secrets.token_hex(16) + "." + secure_filename(file.filename).rsplit(".", 1)[-1].lower()
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cursor.execute("UPDATE users SET PROFILE_PIC=%s WHERE USERNAME=%s", (filename, session["username"]))
                db.commit()
                flash("Profile picture updated!", "success")

        if new_username and new_email:
            try:
                cursor.execute("UPDATE users SET USERNAME=%s, EMAIL=%s WHERE USERNAME=%s", (new_username, new_email, session["username"]))
                db.commit()
                session["username"] = new_username
                flash("Profile updated successfully!", "success")
            except mysql.connector.Error as err:
                flash(f"Error updating profile: {err}", "error")
        
        if new_password:
            if new_password == confirm_password:
                hashed_pw = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET PASSWORD=%s WHERE USERNAME=%s", (hashed_pw, session["username"]))
                db.commit()
                flash("Password updated successfully!", "success")
            else:
                flash("Passwords do not match!", "error")
        cursor.close()
        db.close()
        return redirect(url_for('settings'))
    
    cursor.execute("SELECT * FROM users WHERE USERNAME=%s", (session["username"],))
    user_details = cursor.fetchone()
    cursor.close()
    db.close()
    return render_template("settings.html", username=session["username"], user=user_details, low_stock_threshold=LOW_STOCK_THRESHOLD)

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")
