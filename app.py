from flask import *

app = Flask(__name__)

app.secret_key = "money"
import pymysql
from werkzeug.security import *
from mpesa import *
import os


app.config['UPLOAD_FOLDER'] = os.path.join('static', 'images', 'upload')



def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),       
        user=os.getenv("DB_USER", "root"),            
        password=os.getenv("DB_PASSWORD", ""),        
        database=os.getenv("DB_NAME", "foodmarket")   
    )


@app.route("/")
def Homepage():

    connection = get_connection()
    sql = "select* from Products where product_category = 'Fruits' "
    sql1 = "select* from Products where product_category = 'Vegetables' "
    sql2 = "select* from Products where product_category = 'Dairy' "
    sql3 = "select* from Products where product_category = 'Pastry' "
    sql4 = "select* from Products where product_category = 'Drinks' "

     
    Cursor = connection.cursor()
    Cursor1 = connection.cursor()
    Cursor2 = connection.cursor()
    Cursor3 = connection.cursor()
    Cursor4 = connection.cursor()

  
    Cursor.execute(sql)
    Cursor1.execute(sql1)
    Cursor2.execute(sql2)
    Cursor3.execute(sql3)
    Cursor4.execute(sql4)

   
    fruits = Cursor.fetchall()
    vegetables = Cursor1.fetchall()
    pastry = Cursor2.fetchall()
    dairy = Cursor3.fetchall()
    drinks = Cursor4.fetchall()
    return render_template("index.html", fruits=fruits, vegetables=vegetables, dairy=dairy, pastry=pastry, drinks=drinks)



@app.route("/single/<product_id>")
def single(product_id):


    connection  = get_connection()

  
    sql = "select * from Products where product_id = %s "

    
    cursor = connection.cursor()

    
    cursor.execute(sql, product_id)

  
    product  = cursor.fetchone()
    return render_template("single.html", product=product)


 


@app.route("/uploadproducts", methods=["GET", "POST"])
def upload_products():
    if not session.get('is_admin'):
        return "Access Denied: Admins Only", 403 

    if request.method == "POST":
        
        product_name = request.form['product_name']
        product_desc = request.form['product_desc']
        product_cost = request.form['product_cost']
        product_category = request.form['product_category']
        product_image_name = request.form['product_image_name']

       
        connection  = get_connection()
        Cursor = connection.cursor()

        
        sql = """
            INSERT INTO Products (product_name, product_desc, product_cost, product_category, product_image_name)
            VALUES (%s, %s, %s, %s, %s)
        """
        data = (product_name, product_desc, product_cost, product_category, product_image_name)

        try:
            Cursor.execute(sql, data)
            connection.commit()  
            message = "Product uploaded successfully!"
        except Exception as e:
            connection.rollback() 
            error = f"Error uploading product: {str(e)}"
        finally:
            Cursor.close()
            connection.close()

        return render_template("uploadproducts.html", message=message, error=error)

    return render_template("uploadproducts.html")

    

@app.route('/products')
def products():
  
    page = request.args.get('page', 1, type=int)
    items_per_page = 10  
    offset = (page - 1) * items_per_page

    # Database connection
    connection  = get_connection()
    with connection.cursor() as cursor:
      
        cursor.execute("SELECT COUNT(*) FROM Products")
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + items_per_page - 1) // items_per_page  

     
        cursor.execute("SELECT * FROM Products LIMIT %s OFFSET %s", (items_per_page, offset))
        products = cursor.fetchall()

    connection.close()

    return render_template("products.html", products=products, page=page, total_pages=total_pages)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    connection  = get_connection()
    with connection.cursor() as cursor:
        
        cursor.execute("SELECT * FROM Products WHERE product_id = %s", (product_id,))
        product = cursor.fetchone()

       
        cursor.execute("SELECT image_url, alt_text FROM ProductImages WHERE product_id = %s", (product_id,))
        images = cursor.fetchall()

    connection.close()
    return render_template("product_detail.html", product=product, images=images)


@app.route('/search_products', methods=['GET'])
def search_products():
    query = request.args.get('query', '')  
    page = request.args.get('page', 1, type=int)  
    items_per_page = 10 
    offset = (page - 1) * items_per_page

    # Database connection
    connection  = get_connection()
    with connection.cursor() as cursor:
       
        search_count_sql = """
            SELECT COUNT(*) FROM Products 
            WHERE product_name LIKE %s OR product_category LIKE %s
        """
        cursor.execute(search_count_sql, (f"%{query}%", f"%{query}%"))
        total_items = cursor.fetchone()[0]
        total_pages = (total_items + items_per_page - 1) // items_per_page  

     
        search_sql = """
            SELECT * FROM Products 
            WHERE product_name LIKE %s OR product_category LIKE %s 
            LIMIT %s OFFSET %s
        """
        cursor.execute(search_sql, (f"%{query}%", f"%{query}%", items_per_page, offset))
        search_results = cursor.fetchall()

    connection.close()

    return render_template("products.html", products=search_results, page=page, total_pages=total_pages, query=query)


@app.route('/editproduct/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    connection  = get_connection()
    
    try:
        cursor = connection.cursor()
        
        
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Products WHERE product_id = %s", (product_id,))
            product = cursor.fetchone()
            print(f"Fetched product: {product}")  
            if product:
                return render_template('editproduct.html', product=product)
            else:
                flash("Product not found.", "warning")
                return redirect('/admin')  

        
        elif request.method == 'POST':
            product_name = request.form['name']
            product_desc = request.form['desc']
            product_category = request.form['category']
            product_cost = request.form['cost']
            existing_image = request.form['existing_image']  
            image = request.files['image']

          
            product_image_name = image.filename if image.filename else existing_image

            if image and image.filename:
               
                image.save(f'static/images/{product_image_name}')

            cursor.execute("""
                UPDATE Products SET product_name=%s, product_desc=%s, product_category=%s, product_cost=%s, product_image_name=%s
                WHERE product_id=%s
            """, (product_name, product_desc, product_category, product_cost, product_image_name, product_id))

            connection.commit()
            flash("Product updated successfully!", "success")
            return redirect('/admin') 

    except Exception as e:
        connection.rollback()
        flash(f"Failed to update product: {str(e)}", "danger")
        return redirect('/admin') 

    finally:
        cursor.close()
        connection.close()


@app.route('/delete_product/<int:product_id>', methods=['GET', 'POST'])
def delete_product(product_id):
    connection  = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Products WHERE product_id = %s", (product_id,))
        connection.commit()
        flash("Product deleted successfully!", "success")
    except Exception as e:
        connection.rollback()
        flash("Failed to delete product.", "danger")
    finally:
        cursor.close()
    return redirect('/admin')


@app.route("/manageuser")
def manage_users():
    


    connection  = get_connection()
    try:
        with connection.cursor() as cursor:
        
            sql = "SELECT * FROM user"
            cursor.execute(sql)
            users = cursor.fetchall()
    except Exception as e:
        print(f"Error fetching users: {e}")
        users = []  
    finally:
        connection.close()

  
    return render_template("manageuser.html", users=users)


@app.route("/delete_admin/<int:admin_id>", methods=["POST", "GET"])
def delete_admin(admin_id):
   
    if session.get("is_admin") and session.get("approval_status") == "approved":
        connection  = get_connection()
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM admin WHERE id = %s AND approval_status = 'pending'"
                cursor.execute(sql, (admin_id,))
                connection.commit()
        finally:
            connection.close()
        return redirect("/admin")  
    else:
        return "Access Denied", 403



@app.route("/vieworders")
def view_orders():
    if not session.get('is_admin'):
        return "Access Denied: Admins Only", 403

    connection  = get_connection()
    cursor = connection.cursor()

    try:
        
        sql = """
        SELECT o.order_id, u.username, o.order_total, o.order_status 
        FROM orders o
        JOIN users u ON o.user_id = u.id  -- Assuming 'id' is the primary key in the users table
        """
        cursor.execute(sql)
        orders = cursor.fetchall()
        
    except Exception as e:
        print(f"Error occurred: {e}")
        orders = []  
    finally:
        cursor.close()
        connection.close()

    return render_template("vieworders.html", orders=orders)


@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if not session.get('is_admin'):
        return "Access Denied: Admins Only", 403

    connection  = get_connection()
    cursor = connection.cursor()

    sql = "DELETE FROM user WHERE id = %s"  
    data = (user_id,)

    try:
        cursor.execute(sql, data)
        connection.commit()
        flash("User deleted successfully!", "success")
    except Exception as e:
        connection.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect("/manageuser")


@app.route('/edituser/<int:user_id>', methods=['GET'])
def edit_user(user_id):
   
    connection  = get_connection()
    user = None
    try:
        with connection.cursor() as cursor:
          
            sql = "SELECT id, username, email, gender, phone FROM user WHERE id = %s"
            cursor.execute(sql, (user_id,))
            user = cursor.fetchone() 
    except Exception as e:
        print(f"Error fetching user data: {e}")
        flash("Error retrieving user data.")
    finally:
        connection.close()
    
    if not user:
        flash("User not found.")
        return redirect('/admin')

    return render_template('edituser.html', user=user)


@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):

    username = request.form['username']
    email = request.form['email']
    gender = request.form['gender']
    phone = request.form['phone']


    connection  = get_connection()
    try:
        with connection.cursor() as cursor:
           
            sql = """
                UPDATE user
                SET username = %s, email = %s, gender = %s, phone = %s
                WHERE id = %s
            """
            cursor.execute(sql, (username, email, gender, phone, user_id))
            connection.commit()
            flash("User information updated successfully.")
    except Exception as e:
        print(f"Error updating user: {e}")
        flash("Error updating user information.")
    finally:
        connection.close()


    return redirect('/admin')

@app.route("/about")
def About():
    return render_template("about.html")

@app.route('/readmore')
def readmore():
 
    return render_template("readmore.html")

@app.route("/contactus")
def Contact():
    return render_template("contactus.html")

@app.route("/FAQs")
def FAQs():
    return render_template("FAQs.html")

@app.route("/register", methods=['POST', 'GET'])
def Register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        gender = request.form['gender']
        phone = request.form['phone']
        password = request.form['password']
        user_type = request.form['user_type'] 


        connection  = get_connection()
        cursor = connection.cursor()

        email_check_query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(email_check_query, (email,))
        email_exists = cursor.fetchone()

        if email_exists:
            return render_template("register.html", error="Email already exists!")

        hashed_password = generate_password_hash(password)

        if user_type == "admin":
            admin_check_query = "SELECT * FROM admin WHERE email = %s"
            cursor.execute(admin_check_query, (email,))
            admin_exists = cursor.fetchone()
            if admin_exists:
                return render_template("register.html", error="Email already exists as admin!")

        if user_type == "user":
            sql = "INSERT INTO user (username, email, gender, phone, password) VALUES (%s, %s, %s, %s, %s)"
            data = (username, email, gender, phone, hashed_password)
            cursor.execute(sql, data)

        elif user_type == "admin":
            sql = "INSERT INTO admin (username, email, gender, phone, password) VALUES (%s, %s, %s, %s, %s)"
            data = (username, email, gender, phone, hashed_password)
            cursor.execute(sql, data)

        connection.commit()
        return render_template("register.html", message="Registration successful!")

    return render_template("register.html")


# Password  

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        user_type = request.form['user_type']

    
        connection  = get_connection()
        cursor = connection.cursor()

        if user_type == "user":
           
            sql_user = "SELECT * FROM user WHERE email = %s"
            cursor.execute(sql_user, (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user[5], password):  
                session['key'] = user[1]  
                session['is_admin'] = False  
                return redirect("/")  

        elif user_type == "admin":
           
            sql_admin = "SELECT * FROM admin WHERE email = %s"
            cursor.execute(sql_admin, (email,))
            admin = cursor.fetchone()

            if admin and check_password_hash(admin[5], password):  
                session['key'] = admin[1]  
                session['is_admin'] = True  
                return redirect("/admin")  

        session.clear()
        return render_template("login.html", error="Invalid Login Credentials")

    return render_template('login.html')

@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

     
        print(f"Message from {name} ({email}): {message}")

        flash("Thank you for reaching out! We will get back to you soon.", "success")
        return redirect(url_for('contactus'))
    return render_template('contactus.html')


@app.route("/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    return "File uploaded successfully", 200


 
from flask import session, flash, redirect, render_template, request
import requests
from requests.auth import HTTPBasicAuth
import datetime
import base64

@app.route("/mpesa_payment", methods=["GET", "POST"])
def mpesa_payment():
    total_cost = session.get('total_cost')  
    user_id = session.get('user_id') 

    if request.method == "POST":
        phone = request.form.get("phone")
        
        consumer_key = "GTWADFxIpUfDoNikNGqq1C3023evM6UH"
        consumer_secret = "amFbAoUByPV2rM5A"
        auth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        
        response = requests.get(auth_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
        if response.status_code == 200:
            access_token = "Bearer " + response.json().get('access_token')
        else:
            flash("Failed to get access token", "danger")
            return redirect("/mpesa_payment")

        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
        business_short_code = "174379"
        data_to_encode = business_short_code + passkey + timestamp
        password = base64.b64encode(data_to_encode.encode()).decode('utf-8')

        stk_payload = {
            "BusinessShortCode": business_short_code,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": total_cost,  
            "PartyA": phone,
            "PartyB": business_short_code,
            "PhoneNumber": phone,
            "CallBackURL": "https://modcom.co.ke/job/confirmation.php",
            "AccountReference": "account",
            "TransactionDesc": "Payment for Food Store"
        }

    
        headers = {
            "Authorization": access_token,
            "Content-Type": "application/json"
        }
        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        stk_response = requests.post(stk_url, json=stk_payload, headers=headers)

        if stk_response.status_code == 200:
            
            connection  = get_connection()
            cursor = connection.cursor()
            
         
            order_status = "pending"
            created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            delivery_address = session.get("delivery_address", "Not provided")
            
            query = """
                INSERT INTO orders (user_id, order_total, order_status, created_at, delivery_address)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (user_id, total_cost, order_status, created_at, delivery_address))
            connection.commit()
            
            
            order_id = cursor.lastrowid

            cursor.close()
            connection.close()
            
            flash("Payment request sent. Please check your phone.", "success")
            return redirect(url_for('payment_confirmation', order_id=order_id))
        else:
            flash("Payment failed. Please try again.", "danger")
            return redirect("/mpesa_payment")

    
    return render_template("mpesa_payment.html", total_cost=total_cost)




@app.route("/payment_confirmation/<int:order_id>", methods=["GET", "POST"])
def payment_confirmation(order_id):
    if request.method == "POST":
       
        session.pop("cart", None)
        session.pop("total_cost", None)
        flash("Payment confirmed. Order placed successfully!", "success")
        return redirect("/") 

    
    connection  = get_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM orders WHERE order_id = %s"
    cursor.execute(query, (order_id,))
    order = cursor.fetchone()
    cursor.close()
    connection.close()

    if order:
        return render_template("payment_confirmation.html", order_id=order_id)
    else:
        return "Order not found!", 404




@app.route("/logout")
def Logout():
    session.clear()
    return redirect("/login")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    
    if not session.get("admin_id") or session.get("approval_status") != "approved":
        flash("Access denied. You must be an approved admin.")
        return redirect("/admin_login")


    if request.method == "POST":
        
        if not all(k in request.form for k in ['name', 'desc', 'category', 'cost']) or 'image' not in request.files:
            return "Missing one or more required fields", 400

       
        name = request.form['name']
        desc = request.form['desc']
        category = request.form['category']
        cost = request.form['cost']
        image_file = request.files['image']

       
        if image_file:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_filename = image_file.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

           
            connection  = get_connection()
            try:
                with connection.cursor() as cursor:
                    sql = """
                    INSERT INTO Products (product_name, product_desc, product_category, product_cost, product_image_name)
                    VALUES (%s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql, (name, desc, category, cost, image_filename))
                    connection.commit()
            except Exception as e:
                print(f"Error occurred: {e}")
            finally:
                connection.close()
                return redirect('/admin')


    connection  = get_connection()
    products = {}
    users = []
    orders = []
    pending_admins = []

    try:
        with connection.cursor() as cursor:
            
            categories = ['Fruits', 'Vegetables', 'Dairy', 'Pastry', 'Drinks']
            for category in categories:
                sql = "SELECT * FROM Products WHERE product_category = %s"
                cursor.execute(sql, (category,))
                products[category] = cursor.fetchall()

            cursor.execute("SELECT * FROM user")
            users = cursor.fetchall()

            cursor.execute("SELECT * FROM orders")
            orders = cursor.fetchall()

            sql_pending_admins = "SELECT * FROM admin WHERE approval_status = 'pending'"
            cursor.execute(sql_pending_admins)
            pending_admins = cursor.fetchall()

    except Exception as e:
        print(f"Error fetching data: {e}")
    finally:
        connection.close()

    return render_template("admin.html", products=products, users=users, orders=orders, pending_admins=pending_admins)



@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

       
        connection  = get_connection()
        try:
            with connection.cursor() as cursor:
                
                sql = "SELECT id, username, email, gender, phone, password, status, approval_status FROM admin WHERE email = %s"
                cursor.execute(sql, (email,))
                admin = cursor.fetchone()

                print("Admin fetched from database:", admin)  

             
                if admin:
                    print(f"Admin details: {admin}")  
                    stored_password = admin[5]  

                   
                    if check_password_hash(stored_password, password):  
                        if admin[7] == 'approved':  
                            
                            session['admin_id'] = admin[0]  
                            session['username'] = admin[1]  
                            session['approval_status'] = admin[7]  
                            return redirect('/admin')
                        else:
                            flash("Your account is awaiting approval. Access Denied.")
                            return redirect('/admin_login')
                    else:
                        flash("Invalid email or password.")
                        return redirect('/admin_login')
                else:
                    flash("Invalid email or password.")
                    return redirect('/admin_login')
        except Exception as e:
            print(f"Error during login: {e}")  
            flash(f"An error occurred: {e}")  
            return redirect('/admin_login')
        finally:
            connection.close()

    return render_template('admin_login.html')


@app.route('/approve_admin/<int:admin_id>', methods=['POST'])
def approve_admin(admin_id):
   
    if session.get('approval_status') == 'approved':
        connection  = get_connection()
        try:
            with connection.cursor() as cursor:
               
                sql = "UPDATE admin SET approval_status = 'approved' WHERE id = %s"
                cursor.execute(sql, (admin_id,))
                connection.commit()
            
           
            if admin_id == session['admin_id']:
                session['approval_status'] = 'approved'
            
            return redirect('/admin')  
        except Exception as e:
            print(f"Error occurred while approving admin: {e}")
            return "An error occurred while trying to approve the admin.", 500
        finally:
            connection.close()
    else:
        return "Access Denied", 403  



@app.route("/cart", methods=["GET", "POST"])
def cart():
   
    if 'cart' not in session:
        session['cart'] = []
        session['cart_count'] = 0

    if request.method == "POST":
        product_id = request.form.get('product_id')
        action = request.form.get('action')

      
        if action == 'add':
            if product_id not in session['cart']:
                session['cart'].append(product_id)
                session['cart_count'] += 1
        elif action == 'remove':
            if product_id in session['cart']:
                session['cart'].remove(product_id)
                session['cart_count'] -= 1

        session.modified = True
        return redirect(url_for('cart'))

   
    cart_items = []
    if session['cart']:
        connection  = get_connection()
        try:
            with connection.cursor() as cursor:
                
                for product_id in session['cart']:
                    sql = "SELECT * FROM Products WHERE product_id = %s"
                    cursor.execute(sql, (product_id,))
                    product = cursor.fetchone()
                    if product:
                        cart_items.append(product)
        finally:
            connection.close()

    return render_template("cart.html", cart_items=cart_items)


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    cart_items = []
    total_cost = 0

    
    if 'cart' in session and session['cart']:
        connection  = get_connection()
        try:
            with connection.cursor() as cursor:
                for product_id in session['cart']:
                    sql = "SELECT * FROM Products WHERE product_id = %s"
                    cursor.execute(sql, (product_id,))
                    product = cursor.fetchone()
                    if product:
                        cart_items.append(product)
                        
                        total_cost += product[3] if product[3] else 0 
        finally:
            connection.close()

    
    session['total_cost'] = total_cost

   
    if request.method == "POST":
        phone = request.form.get("phone")

        
        consumer_key = "GTWADFxIpUfDoNikNGqq1C3023evM6UH"
        consumer_secret = "amFbAoUByPV2rM5A"
        auth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        
        response = requests.get(auth_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
        if response.status_code == 200:
            access_token = "Bearer " + response.json().get('access_token')
        else:
            flash("Failed to get M-Pesa access token", "danger")
            return redirect(url_for('checkout'))

        
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
        business_short_code = "174379"
        data_to_encode = business_short_code + passkey + timestamp
        password = base64.b64encode(data_to_encode.encode()).decode('utf-8')

        
        stk_payload = {
            "BusinessShortCode": business_short_code,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": total_cost,
            "PartyA": phone,
            "PartyB": business_short_code,
            "PhoneNumber": phone,
            "CallBackURL": "https://modcom.co.ke/job/confirmation.php",  
            "AccountReference": "FoodStorePurchase",
            "TransactionDesc": "Payment for food store items"
        }

        
        headers = {
            "Authorization": access_token,
            "Content-Type": "application/json"
        }
        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        stk_response = requests.post(stk_url, json=stk_payload, headers=headers)

        if stk_response.status_code == 200:
            # Clear cart after payment request is successful
            session['cart'] = []
            session['cart_count'] = 0
            flash("Payment request sent. Please check your phone.", "success")
            return redirect(url_for('payment_confirmation'))
        else:
            flash("Payment failed. Please try again.", "danger")
            return redirect(url_for('checkout'))

   
    return render_template("checkout.html", cart_items=cart_items, total_cost=total_cost)


@app.route('/delivery', methods=['POST'])
def delivery():
    
    address = request.form.get('address')
    phone = request.form.get('phone')
    total_cost = request.form.get('total_cost')

  
    connection  = get_connection()
    try:
        with connection.cursor() as cursor:
            
            query = """
            INSERT INTO delivery (address, phone, total_cost, status)
            VALUES (%s, %s, %s, 'Pending')
            """
            cursor.execute(query, (address, phone, total_cost))
            connection.commit()
        
        flash("Delivery has been scheduled successfully.", "success")
        return redirect(url_for('ordersummary'))
    
    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred while scheduling delivery. Please try again.", "danger")
        return redirect(url_for('checkout'))

    finally:
        connection.close()
        
@app.route('/place_order', methods=['POST'])
def place_order():
    user_id = 1  
    order_total = request.form['total_cost']  
    order_status = 'pending' 
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
    delivery_address = ""
    
    connection  = get_connection()
    cursor = connection.cursor()

   
    query = """
    INSERT INTO orders (user_id, order_total, order_status, created_at, delivery_address)
    VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (user_id, order_total, order_status, created_at, delivery_address))
    connection.commit()

 
    order_id = cursor.lastrowid

    cursor.close()
    connection.close()

  
    return redirect(url_for('mpesa_payment', order_id=order_id))

# Route to handle payment
# @app.route('/mpesa_payment/<int:order_id>', methods=['GET', 'POST'])
# def mpesa_payment(order_id):
#     if request.method == 'POST':
#         # Process payment here, e.g., via M-Pesa or other methods
#         # Assuming payment was successful
        
#         payment_status = 'paid'  # After successful payment, update the order to 'paid'
#         connection = pymysql.connect(host="localhost", user="root", password="", database="foodmarket")
#         cursor = connection.cursor()

#         # Update the order status to 'paid' after successful payment
#         update_query = "UPDATE orders SET order_status = %s WHERE order_id = %s"
#         cursor.execute(update_query, (payment_status, order_id))
#         connection.commit()

#         cursor.close()
#         connection.close()

#         # Redirect to a success page or order summary
#         return render_template('payment_confirmation.html', order_id=order_id)
    


@app.route('/ordersummary/<int:order_id>')
def order_summary(order_id):
    connection  = get_connection()
    cursor = connection.cursor()

   
    query = "SELECT order_id, order_total, order_status, created_at, delivery_address FROM orders WHERE order_id = %s"
    cursor.execute(query, (order_id,))
    order = cursor.fetchone()

    cursor.close()
    connection.close()

    if order:
        return render_template('ordersummary.html', order=order)
    else:
        return "Order not found!", 404      
        
        

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')

    
    connection  = get_connection()
    try:
        with connection.cursor() as cursor:
          
            sql = "INSERT INTO subscribers (email) VALUES (%s)"
            cursor.execute(sql, (email,))
            connection.commit()
            flash("Successfully subscribed to the newsletter!", "success")
    except pymysql.IntegrityError:
        flash("This email is already subscribed.", "warning")
    except Exception as e:
        flash("An error occurred. Please try again.", "danger")
        print("Error:", e)
    finally:
        connection.close()

    return redirect('/')



if __name__ == "__main__":
   
    port = int(os.environ.get("PORT", 4000))
  

    app.run(host="0.0.0.0", port=port, debug=False)