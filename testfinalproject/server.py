from flask import Flask,  render_template,  request, jsonify, url_for, redirect
import string
from lookup import *
from fuzzer import *
import sqlite3 as sq
import time
import random
from firewall_detection import get_firewall


app = Flask(__name__)


tasks = {}


@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/firewall')
def firewall():
	return render_template('firewall.html')

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route('/signup')
def signup():
	return render_template('signup.html')

@app.route('/cs')
def cs():
	return render_template('cs.html')



#-- when user submits URl into page 
@app.route('/location', methods=['POST','GET'])
def location():
    if request.method == 'POST':
        webpage = request.form['web']
        scan_type = request.form['0']
        if scan_type == 'Location':
            return look_up(webpage) 
    else:
        return render_template('location.html')
    



 
#-- when user submits URl into page   
@app.route('/fuzzy', methods=['POST', 'GET'])
def fuzzy():
    if request.method == 'POST':
        website = request.form['website']
        scan_type = request.form['O']
        if scan_type == 'Scan':
            return fuzz_result(website)
    else:
        return render_template('fuzzy.html')
    


def look_up(webpage):
   #-- get results from scan
    results = whois(webpage)
    #-- display results
    return render_template('lookup.html', results=results)








    

@app.route('/fuzzer/fuzcs/<string:UF>')
def updateFuzzer(UF):
       #-- Returning the results of the fuzzer scan
    data = {"valid": True}
    if tasks[UF].is_alive():
        data["progress"] = round(tasks[UF].count /0.90)
        data["current"] = tasks[UF].current
    else:
        data["progress"] = "finished"

    return jsonify(data), 200

@app.route('/show_result/<string:UF>')
 #-- get results from scan and displays them
def show_result(UF):
    results = tasks[UF].results
    return render_template('fuzzresult.html', results=results)


def fuzz_result(website):
     #-- Adding a randon key per scan for fuzz scan
    keychain = randomkey()
    thr = URlFuzz(website)
    thr.start()
    tasks[keychain] = thr
    return render_template('loader.html', fuzz_key=keychain)

def randomkey():
     #-- creates key 
    keychain = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits)for _ in range(15))
    if keychain in tasks:
     keychain = randomkey()
    return keychain













#-- when user submits URl into page firewall
@app.route('/detect_firewall', methods=['POST'])
def detect_firewall():
	websiteurl = request.form.get('URL')
	Waf = request.form.get('Waf')
	response = get_firewall(websiteurl, Waf)
	return render_template('firewall.html', result=response)










#-- creating the database with table, 
def create():
    db = sq.connect("site.sqlite")
    cur = db.cursor()
    print(" database connection!")
    time.sleep(1)
    cur.execute(""" CREATE TABLE IF NOT EXISTS users(name TEXT, email TEXT, password BLOB) """)
    db.commit()
   

#-- insert  sign up information in database from user
def insert (name, email, password):
    db = sq.connect("site.sqlite")
    cur = db.cursor()
    cur.execute("""INSERT INTO users (name, email, password) VALUES(?,?,?)""",(name,email,password))
    db.commit()
    db.close()




#-- sees if email is already in database
def check_data(email):
    db = sq.connect("site.sqlite")
    cursor = db.cursor()
    cursor.execute("""SELECT email FROM users WHERE email=(?)""",(email,))
    data = cursor.fetchall()
    if len(data) == 0:
        return True
#--  check correct login info
def check_login_data(email, password):
    db = sq.connect("site.sqlite")
    cursor = db.cursor()
    cursor.execute("""SELECT email FROM users WHERE email=(?)""",(email,))
    data = cursor.fetchall()
    print(data)
    if len(data) > 0:
        cursor.execute("""SELECT password FROM users WHERE password=(?)""",(password,))
        data = cursor.fetchall()
        print(data)
        if len(data) > 0:
            return True

create()







#-- the registery page 
@app.route("/register_success", methods = ["POST", "GET"])
def register_success():
    if request.method == "POST":
        email = request.form["email"]
        if check_data(email):
            email = request.form["email"]
            name = request.form["name"]
            password = request.form["password"]
            print(name)
            print(email)
            print(password)
            insert(name, email, password)
            return render_template("register_success.html")
        else:
            return render_template("register_fail.html")

#-- the registery fail page 
@app.route("/register_fail")
def register_fail():
    return render_template("register_fail.html")


#-- the log in pages
@app.route("/login_success", methods = ["POST", "GET"])
def login_success():
    if request.method == "POST":
        email = request.form["email"]
        print(email)
        password = request.form["password"]
        print(password)
        if check_login_data(email, password):
            return render_template("login_success.html")
        else:
            return render_template("login_fail.html")




if __name__ == "__main__":
    app.run(debug=False)
