from flask import Flask, request, render_template, url_for, redirect,session, cli
import sqlite3
from flask_session import Session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt
import click

# defualt admin :- 
# username = 'admin_iitm' 
# password = 'admin_pass'


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
# for migration flask db init

class Pro(db.Model):
    pro_id = db.Column(db.Integer, primary_key = True)
    pro_name = db.Column(db.String, nullable = False)
    pro_username = db.Column(db.String, unique = True, nullable = False)
    pro_email = db.Column(db.String, nullable = False)
    pro_password = db.Column(db.String, nullable = False)
    pro_address= db.Column(db.String, nullable = False)
    pro_pincode = db.Column(db.String(6), nullable = False)
    pro_date = db.Column(db.Integer, nullable = False)
    pro_service = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable = False)
    pro_exp = db.Column(db.String, nullable = False)
    pro_desc = db.Column(db.String, nullable = False)
    pro_rating = db.Column(db.Float)

    def __init__(self,pro_name,pro_username,pro_email,pro_password,pro_address,pro_pincode,pro_service,pro_exp,pro_desc):
        self.pro_name=pro_name.capitalize()
        self.pro_username=pro_username
        self.pro_email=pro_email
        self.pro_password=bcrypt.hashpw(pro_password.encode('utf-8'), bcrypt.gensalt())
        self.pro_address=pro_address
        self.pro_pincode=pro_pincode
        self.pro_date=datetime.now().strftime('%Y-%m-%d')
        self.pro_service=pro_service
        self.pro_exp=pro_exp
        self.pro_desc=pro_desc
        self.pro_rating = 0
    def check_pass(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.pro_password)

class Cust(db.Model):
    cust_id = db.Column(db.Integer, primary_key = True)
    cust_name = db.Column(db.String, nullable = False)
    cust_username = db.Column(db.String, unique = True, nullable = False)
    cust_email = db.Column(db.String, nullable = False)
    cust_password = db.Column(db.String, nullable = False)
    cust_address= db.Column(db.String, nullable = False)
    cust_pincode = db.Column(db.String(6), nullable = False)
    cust_date = db.Column(db.Integer, nullable = False)
    def __init__(self,cust_name,cust_username,cust_email,cust_password,cust_address,cust_pincode):
        self.cust_name=cust_name.capitalize()
        self.cust_username=cust_username
        self.cust_email=cust_email
        self.cust_password=bcrypt.hashpw(cust_password.encode('utf-8'), bcrypt.gensalt())
        self.cust_address=cust_address
        self.cust_pincode=cust_pincode
        self.cust_date= datetime.now().strftime('%Y-%m-%d')

    def check_pass(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.cust_password)
class Services(db.Model):
    service_id= db.Column(db.Integer, primary_key = True)
    service_name= db.Column(db.String(50)  )
    service_desc= db.Column(db.String(200) )
    service_b_price= db.Column(db.Float() ,nullable= False)
    time_required =db.Column(db.String,  nullable=False)

    def __init__(self, service_type, desc, b_price, time_required ):
        self.service_name = service_type.capitalize()
        self.service_b_price= b_price
        self.service_desc=desc
        self.time_required = time_required

class Service_request(db.Model):
    req_id=db.Column(db.Integer, primary_key = True)
    req_service_id =  db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    req_cust_id= db.Column(db.Integer, db.ForeignKey('cust.cust_id'), nullable=False)
    req_pro_id= db.Column(db.Integer, db.ForeignKey('pro.pro_id'), nullable=True)
    req_date =db.Column(db.Integer,  nullable=False)
    req_status = db.Column(db.String,  nullable=False)
    req_action_date =db.Column(db.Integer)
    req_completed_date =db.Column(db.Integer)
    req_rating =db.Column(db.Float)
    req_remark =db.Column(db.Integer)
    # req_act_date
    
    def __init__(self, service_id, cust_id, pro_id,status,):
        self.req_cust_id=cust_id
        self.req_pro_id=pro_id
        self.req_service_id=service_id
        self.req_status = status
        self.req_date= datetime.now().strftime('%Y-%m-%d')
        self.req_action_date = None
        self.req_completed_date  = None
        self.req_rating = None
        self.req_remark = None

class Admin(db.Model):
    admin_id=db.Column(db.Integer, primary_key = True)
    admin_username = db.Column(db.String,  nullable=False)
    admin_password = db.Column(db.String,  nullable=False)
    admin_email = db.Column(db.String,  nullable=False)
    def __init__( self, username, password, email):
        self.admin_username= username
        self.admin_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.admin_email = email 
    def check_pass(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.admin_password)



""" table init """
with app.app_context():
    db.create_all()

"""following 3 lines for cookies setup"""

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'
Session(app)
# INSERT INTO customers (c_joined) VALUES(strftime('%s','now')); it store time now 
# GET DATE from db 
# SELECT strftime('%Y-%m-%d', c_joined, 'unixepoch') AS date FROM customers;  
# 2024-09-19
# sqlite>
#static files 
# url_for('static', filename='style.css')

# def db_connect():
#     return  sqlite3.connect("easyhome.db")

# def registration_db():
#     conn= db_connect()
@app.cli.command('create_superuser')
@click.option('--username', prompt ='Enter Username')
@click.option('--email', prompt ='Email')
@click.option('--password1', prompt ='Enter Password', hide_input = True)
@click.option('--password2', prompt ='Enter Password Again', hide_input = True)
def create_superuser(username, email, password1, password2):
    if password1 ==password2: 
            username = username
            admins = Admin.query.filter(Admin.admin_username == username).first()
            userp= Pro.query.filter_by(pro_username = username).first()
            userc= Cust.query.filter_by(cust_username = username).first()
            # print(admins)
            if admins or userp or userc:
                return click.echo('Username arlready Exist')
            email = email
            new_admin = Admin(username=username, password=password1, email=email)
            db.session.add(new_admin)
            db.session.commit()
            click.echo(f'hy {username} superuser created successfully')
    else:
        return click.echo('Password Not Match')
    

@app.route("/")
def home():
    username=session.get("username")
    return render_template("index.html",username=username)

@app.route("/register", methods=['POST', 'GET'])
def register_pro():
    username= request.form.get("username")
    # print(list(session.keys()))
    # if session[username]:
    #     if session[username]== username:
    #         return redirect("/verification")
    # k1=cursor.execute('SELECT * FROM Services').fetchall()
    k1 = Services.query.all()
    # k2 =[i.service_name for i in k1]
    flag=False
    exp1=["Fresher","1","2","3","4","5","5+"]

    if request.method== "POST":
        name= request.form.get("name")
        email= request.form.get("email")
        pass1= request.form.get("pass")
        exp= request.form.get("exp")
        desc= request.form.get("desc")
        username= request.form.get("username")
        service_type= request.form.get("service")
        address= request.form.get('address')
        pincode= str(request.form.get('pincode'))
        date1 = datetime.now().strftime('%Y-%m-%d')
        # username_db =[i[0] for i in username_db] 
        # print(username, username_db)
        print(pass1,'ppppppppppppp',service_type)
        username_db= Pro.query.filter_by(pro_username=username).first()
        pro1=Pro.query.all()
        print(pro1)
        print(username_db)
        if username_db :
            flag="username already exist"
            # return render_template("reg.html", flag1=flag1)
        elif username:
            new_user=Pro(pro_name= name,pro_username= username,pro_email=email,pro_password= pass1,pro_address= address,pro_pincode=pincode,pro_service=service_type,pro_exp=exp,pro_desc=desc)
            print(new_user)
            db.session.add(new_user)
            db.session.commit()

            flag= "Submission success"

            return redirect("/verification")
    return render_template("register_p.html",flag=flag ,k1=k1,exp=exp1)



@app.route("/register_c", methods=['POST', 'GET'])
def register_c():
    flag= False
    if request.method == "POST":
        name= request.form.get("name")
        email= request.form.get("email")
        pass1= request.form.get("pass")
        username= request.form.get("username")
        address= request.form.get('address')
        pincode= str(request.form.get('pincode'))
        date1 = datetime.now().strftime('%Y-%m-%d')
        # username_db =[i[0] for i in username_db] 
        # print(name, email, username, username_db)
        username_db= Cust.query.filter_by(cust_username=username).first()
        pro1=Cust.query.all()
        print(pro1)
        print(username_db)
        if username_db :
            flag="username already exist"
            # return render_template("reg.html", flag1=flag1)
        elif username:
            new_user=Cust(cust_name= name,cust_username= username,cust_email=email,cust_password= pass1,cust_address= address,cust_pincode=pincode,)
            print(new_user)
            db.session.add(new_user)
            db.session.commit()
            return redirect("/verification")

    return render_template("register_c.html", flag=flag)


@app.route("/login", methods=['POST','GET'])
def login():
    username=request.form.get("username")
    pass1=request.form.get("pass")
    flag= False
    userp= Pro.query.filter_by(pro_username = username).first()
    userc= Cust.query.filter_by(cust_username = username).first()
    admin= Admin.query.filter_by(admin_username = username).first()
    print(admin,'admin1')
    print(userp, userc)
    print(username, pass1)
    if userp:
        print(userp.pro_name)
        session['type1']= "pro"
        if userp.check_pass(pass1):
            session['username']=username
            flag = "login success"
            return redirect(f"/dashboard")
        else:
            flag='Incorrect password'
    elif userc:
        session['type1']= "cust"
        if userc.check_pass(pass1):
            session['username']=username
            flag = "login success"
            return redirect(f"/dashboard")
        else:
            flag='Incorrect password'
    elif admin:
        print('admin2')
        session['type1']= "admin"
        if admin.check_pass(pass1):
            session['username']=username
            flag = "login success"
            return redirect(f"/admin")
        else:
            flag='Incorrect password'
    else: flag= 'Username Not Found'
    return render_template("login.html",flag=flag)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/admin", methods = ['POST','GET'])
def admin():
    if session['type1'] == 'admin':
        return render_template("admin.html")
    else:
        return redirect('/dashboard')
'''   
@app.route("/dashboard", methods=["POST",'GET'])
def dashboard():
    p_service= request.form.get('service')
    p_name= request.form.get("name")
    print(p_service,"ghhhhhhg")
    service_pro = 1
    # service_pro=conn.execute("SELECT * FROM serve_pro WHERE pro_service =?", (p_service)).fetchone()
    return render_template("dashboard.html",p= p_service, sp=service_pro) 
'''


    # return  render_template("login.html")
@app.route("/dashboard", methods=['POST','GET'])
def dashboard_user():
    # print(session["type1"])
    service1 = False
    user = False
    request_created= False
    typek = False
    s1= None
    # print("sdfsdfs",session['type1'], session)
    if 'type1' in session:
        k=session.get('username')
        if session['type1']== 'cust':
            typek = 'cust'
            user = Cust.query.filter_by(cust_username = k).first()
            request_created = Service_request.query.filter_by(req_cust_id = user.cust_id).all()
            # print(request_created)
            s1 = db.session.query(Cust.cust_name, Pro.pro_name, Pro.pro_username,Services.service_name, Service_request.req_date, Service_request.req_status, Service_request.req_id).join(Services,
            Service_request.req_service_id == Services.service_id).join(Pro, Service_request.req_pro_id == Pro.pro_id).join(Cust,
            Service_request.req_cust_id == Cust.cust_id).filter(Service_request.req_cust_id==user.cust_id).all()
            
            # print(s1, "kkl")
            
            # print(user)
        elif session['type1']== 'pro':
            typek = 'pro'
            user = Pro.query.filter_by(pro_username = k).first()
            # print(user.pro_service)
            service1=Services.query.filter_by(service_id = user.pro_service).first()
            request_created = Service_request.query.filter_by(req_pro_id = user.pro_id).all()
            s1 = db.session.query(Cust.cust_username,Services.service_name,Service_request.req_date, Service_request.req_status).join(Services,  Service_request.req_service_id == Services.service_id).join(Cust, Service_request.req_cust_id == Cust.cust_id).all()
            s1 = db.session.query(Cust.cust_name, Cust.cust_address,Cust.cust_pincode, Pro.pro_name, Pro.pro_username, Services.service_name, Service_request.req_date, Service_request.req_status, Service_request.req_id).join(Services,
            Service_request.req_service_id == Services.service_id).join(Pro, Service_request.req_pro_id == Pro.pro_id).join(Cust,
            Service_request.req_cust_id == Cust.cust_id).filter(Service_request.req_pro_id==user.pro_id).all()
            
            # s2 = [i.cust_name_1 for i in s1 ]
            # print(s1, "kwerw")
            # print(s2,'kl')
            print(request_created)
            print(user)
        elif session['type1'] == 'admin':
            print('admin')

        else:
            return redirect("/login")
    else:
        return redirect("/login")
    if request.method == 'POST':
        accept = request.form.get('accept')
        reject = request.form.get('reject')
        close = request.form.get('close')
        rating = request.form.get("rating")
        remark = request.form.get("remark")
        print(accept, reject)
        if accept:
            # print('accept')
            req_accept(accept)

            # print(req.req_status)
        elif reject:
            req_reject(reject)
        elif close:
            req_close(close)
            return redirect(f"/remarks/{close}")
        
            # print("reject")
    print(typek)
    return render_template("dashboard_user.html",serv1 = service1,s1=s1,request_created=request_created, type1 = typek ,user= user)

@app.route("/admin/pro")
def admin_pro():
    pros= Pro.query.all()

@app.route("/verification")
def verify():

    return render_template("verify.html")
@app.route("/services")
def all_serv():
    services =Services.query.all()
    return render_template("services.html", services=services)

 
@app.route("/service", methods=['POST', 'GET'])
def service():
    serv=Services.query.all()
    del1= request.form.get("del")
    edit1=request.form.get("edit1")
    print(del1)
    if del1:
        service1= Services.query.get(del1)
        if service1:
            print(service1)
            db.session.delete(service1)
            db.session.commit()
    if edit1:
        service1= Services.query.get(edit1)
        if service1:
            flag2=service1.service_id
            return redirect(f"/service/{flag2}" )
            print(service1.service_name)
            
    return render_template("service.html",serv=serv)
  
@app.route("/service/<flag>", methods=["POST",'GET'])
def service_add(flag):
    serv=flag
    print(serv,"fghgfghhf")
    flag2 = False
    flag1= False
    service1= None
    if flag== "add":
        flag2 = True
        if request.method=='POST':
            print(121231)
            service_type= request.form.get('service_name')
            desc= request.form.get('desc')
            base_p= request.form.get('service_price')
            time_required= request.form.get('service_time')
            new_service = Services( service_type= service_type,desc=desc, b_price=base_p, time_required=time_required)
            db.session.add(new_service)
            db.session.commit()
            flag = "Service Added Successfully"
    else:

        service1=Services.query.filter_by(service_id =serv).first()
        flag1=True
        if request.method=='POST' and service1:
            service1.service_name= request.form.get('service_name')
            service1.service_desc= request.form.get('desc')
            service1.service_b_price= request.form.get('service_price')
            service1.time_required= request.form.get('service_time')
            db.session.commit()
            return redirect("/service")
    return render_template("service_add.html", flag1=flag1,flag2=flag2, services=service1)




@app.route("/service_page/<service_id>", methods = ['POST','GET'])
def service_page(service_id):
    service_id1 = service_id
    typek = session["type1"]
    if request.method =='POST':
        # print()
        pro_req_id = request.form.get("pro_id")
        print(pro_req_id, 'dfsdfdfsdf')
        if pro_req_id:
            print(2344234242)

            return redirect(f"/service/pro/{pro_req_id}")

    services =Services.query.filter_by(service_id = service_id1).first()
    pro1 = Pro.query.filter_by(pro_service= service_id1).all()
    pro2 = db.session.query(Pro.pro_name, Pro.pro_desc, Pro.pro_date, Pro.pro_email,Pro.pro_pincode, Pro.pro_id,
            Services.service_b_price, Pro.pro_rating).join(Services, 
            Pro.pro_service == Services.service_id).filter(Pro.pro_service == service_id1).order_by(Pro.pro_rating).all()
    # print(pro2[0])
    # rating = user_rating(2)
    # print(rating)
    pro2=pro2[::-1]
    return render_template("service_page.html",pros= pro2,pro2= pro2, type1 = typek, services=services)


@app.route("/service/pro/<pro_req_id>", methods = ['POST','GET'])
def service_pro(pro_req_id):
    return redirect(f"/service/book/{pro_req_id}")

@app.route("/service/book/<pro_id>", methods =['POST','GET'])
def book(pro_id):
    pro_id1 = pro_id
    s1 = None
    # print(s1)
    if session :
        if request.method == 'POST':
            status1 = "service requested"
            username = session['username']
            cust_d = Cust.query.filter_by(cust_username = username).first()
            pro_d = Pro.query.filter_by(pro_id = pro_id).first()
            cust = cust_d.cust_id
            serv_id = pro_d.pro_service 
            booking= Service_request(service_id=serv_id , cust_id= cust, pro_id= pro_id,  status=status1)
            db.session.add(booking)
            db.session.commit()
            return redirect("/booking_success")
        else:
            s1 = Pro.query.filter(Pro.pro_id == pro_id1).first()
            print(s1, "sdfsddf")
    else:
        return redirect('/login')
    return render_template("booking.html", s1 = s1)

# @app.route("/accept/<req_id>")
def req_accept(req_id):
    r_id = req_id
    req = Service_request.query.filter(Service_request.req_id == r_id).first()
    if req:
        req.req_status = "Accepted"
        req.req_action_date = datetime.now().strftime('%Y-%m-%d')
        db.session.commit()

# @app.route("/reject/<req_id>")
def req_reject(req_id):
    r_id = req_id
    req = Service_request.query.filter(Service_request.req_id == r_id).first()
    # print(req)
    if req:
        req.req_status = "Rejected"
        req.req_action_date = datetime.now().strftime('%Y-%m-%d')
        req.req_completed_date  =  datetime.now().strftime('%Y-%m-%d')
        db.session.commit()

# @app.route("/close/<req_id>")
def req_close(req_id):
    r_id = req_id
    req = Service_request.query.filter(Service_request.req_id == r_id).first()
    if req:
        req.req_status = "Closed"
        req.req_completed_date  =  datetime.now().strftime('%Y-%m-%d')
        db.session.commit()

@app.route("/remarks/<req_id>", methods =['POST', 'GET'])
def remarks(req_id):
    r_id = req_id
    req = Service_request.query.filter(Service_request.req_id == r_id).first()
    pr_id = req.req_pro_id
    pro_d = Pro.query.filter(Pro.pro_id == pr_id).first()
    if request.method == 'POST':
        rating = request.form.get("rating")
        remark = request.form.get("remark")
        if req:
            req.req_rating = rating
            req.req_remark = remark 
            db.session.commit()
            pro_d.pro_rating = user_rating(pr_id)
            db.session.commit()
            return redirect("/dashboard")

    return render_template("rating.html")
# @app.route("/avg/<pro_id>")
def user_rating(pro_id):
    pr1= pro_id
    all1 = Service_request.query.filter(Service_request.req_pro_id == pr1).all()
    print(all1)
    count, total , flag= 0, 0, False
    for i in all1 :
        if i.req_rating:
            count +=1
            total += i.req_rating 
            flag = True
            print(i.req_rating, total, count)
    if flag : return f"{total/count:.2f}"
    return 0 
    # return render_template("avg.html", avg= avg)
# print("avg")
# print(avg(1))
'''name='name'
username= "user"
email="em"
pass1= "pass323232"
address= "add"
pincode=234234
date1=233223
service_type="serv"
exp="exp"
desc="desc"
new_user=Pro(pro_name=name,pro_username= username,pro_email=email,pro_password= pass1,pro_address= address,pro_pincode=pincode,pro_service=service_type,pro_exp=exp,pro_desc=desc)
# print(new_user.set_pass('123'))
print(new_user.pro_service)
print(new_user.check_pass("pass32323"))

            '''