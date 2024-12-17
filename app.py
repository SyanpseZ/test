from flask import Flask, request, jsonify, session, redirect, render_template, send_file
import os, bcrypt, uuid
import mysql.connector # or other database drivers
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this!

# Database connection details
db_config = {
    "host": "localhost",
    "user": "myuser",
    "password": "mypassword",
    "database": "myapp_db",
    "port": 3306,
}


@app.route("/", methods=["GET"])
def home():
    user = get_logged_in_user()
    return render_template("index.html", session=session)



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    # Retrieve input values
    username = request.form.get("username")
    password = request.form.get("password")
    secret_key = request.form.get("Secret")  # Custom key input

    # Custom Secret key validation
    REQUIRED_SECRET_KEY = "866702177882603580"  # Change this key to your desired value
    if secret_key != REQUIRED_SECRET_KEY:
        return "Invalid Secret Key. You are not allowed to create an account.", 403

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        # Insert into the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        return "User Created, please <a href='/login'>Login</a>"
    except Exception as e:
        return f"Error on signup: {str(e)}"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
      return render_template("login.html")
    username = request.form.get("username")
    password = request.form.get("password")

    try:
      conn = mysql.connector.connect(**db_config)
      cursor = conn.cursor()
      cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
      result = cursor.fetchone()

      cursor.close()
      conn.close()

      if result:
          user_id, stored_hash = result
          if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # Password matches
            session['user_id'] = user_id
            session['username'] = username
            return redirect('/upload')
          else:
              return "Invalid password", 401
      else:
          return "Invalid username", 401

    except Exception as e:
      return f"Error in Login {str(e)}"

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect('/login')  # Redirect to the login page


def is_logged_in():
    return 'user_id' in session

def get_logged_in_user():
    if is_logged_in():
        return {"id": session["user_id"], "username": session["username"]}
    return None

@app.route('/upload', methods=['GET', 'POST'])
def upload_image():
    if not is_logged_in():
        return "Login Required", 401
    if request.method == 'GET':
      return render_template("upload.html")

    user = get_logged_in_user()

    if 'image' not in request.files:
        return "No image part in the request", 400

    image_file = request.files['image']
    if image_file.filename == '':
        return "No image selected", 400

    # Check the filename is valid
    if not valid_file_extension(image_file.filename):
        return "Invalid file extension", 400

    filename = str(uuid.uuid4()) + os.path.splitext(image_file.filename)[1] #generate a uuid
    filepath = os.path.join("uploads", filename)
    try:
      image_file.save(filepath)
    except Exception as e:
      return f"Error Saving Image: {e}", 500

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        sql = "INSERT INTO images (user_id, filename, upload_date, file_path) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (user['id'], filename, datetime.now(), filepath))
        conn.commit()
        cursor.close()
        conn.close()

        image_url = f"/get-image/{filename}"

        return f"Image uploaded successfully! <a href='{image_url}'>View image</a>"
    except Exception as e:
        return f"Error on db upload {e}"


@app.route("/image/<filename>", methods=["GET"])
def get_image(filename):
    if not is_logged_in():
        return "Login Required", 401
    # Construct the file path
    filepath = os.path.join("uploads", filename)
    return send_file(filepath)

# helper function to check filename extension
def valid_file_extension(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to create upload directory if not exists
if not os.path.exists("uploads"):
    os.mkdir("uploads")


if __name__ == '__main__':
    app.run(debug=True)