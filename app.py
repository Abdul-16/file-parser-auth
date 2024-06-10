from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow import ValidationError
import pandas as pd
from hashlib import sha256
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///excel.db'
app.config['SECRET_KEY'] = 'nrvlfiw7534qwb usbei[8rs]'
db = SQLAlchemy(app)
ma = Marshmallow(app)


class Students(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    roll_no = db.Column(db.Integer, nullable=False, primary_key=True) #unique=True)
    name = db.Column(db.String(32), nullable=False)
    marks = db.Column(db.Integer, nullable=False)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)

class User_Schema(ma.Schema):
    class Meta:
        fields = ['id', 'email', 'password']

class Students_schema(ma.Schema):
    class Meta:
        fields = ['roll_no','name','marks']

user_schema = User_Schema()
student_schema = Students_schema()
students_schema = Students_schema(many=True)

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'message': 'Authorization header is missing or invalid'}), 401

        token = token.replace('Bearer ', '')
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # print(data)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return func(*args, **kwargs)

    return wrapper

@app.route('/login', methods=['POST'])
def login():
    data = request.json 
    try:
        va = user_schema.load(data)
    except ValidationError as errors:
        return jsonify({'message': 'Validation error', 'errors': errors}), 422
    print(va)
    user = Users.query.filter_by(email=va.get('email')).first()
    
    if user and user.password == sha256(va['password'].encode('utf-8')).hexdigest():
        payload = {'username':va['email'], 'exp': datetime.utcnow() + timedelta(minutes=1)}        
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token, 'message':'login successful'}), 200
    else:
        return jsonify({'message': 'invalid credentials'})

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    try:
        va = user_schema.dump(data)
    except ValidationError as errors:
        return jsonify({'message': 'Validation error', 'errors': errors}), 422
    ss = Users(email=data['email'], password=sha256(data['password'].encode('utf-8')).hexdigest())
    db.session.add(ss)
    db.session.commit()
    return jsonify({'message':'sign up was successful'}), 200


@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/read', methods=['GET'])
@login_required
def readEx():
    try:
        if records := Students.query.all():
            valid = students_schema.dump(records)
        else:
            return jsonify({'message':'No records found'}), 404
    except ValidationError as error:
        return jsonify({'message':'ValidationError', 'Error':error}), 400
    return jsonify(valid), 200


@app.route('/upload', methods=['POST'])
@login_required
def uploadEx():
    file = request.files.get('data')
    # print((request.form))
    if not file or file.filename == '':
        return jsonify({'message': 'No file selected'}), 400

    if file.filename.endswith('.xlsx'):
        # try:
        df = pd.read_excel(file)
        df.columns = [col.lower() for col in df.columns]
        if {'roll_no', 'name', 'marks'}.issubset(df.columns):
            try:
                df = df[['roll_no', 'name', 'marks']]
                df.dropna(inplace=True)
                m_data = students_schema.load(df.to_dict(orient='records'))
            # print(m_data)
            except ValidationError as errors:
                return jsonify({'message': 'Validation error', 'errors': errors}), 422

            roll_nos = {student.roll_no for student in Students.query.all()}

            for entry in m_data:
                if entry.get('roll_no') not in roll_nos:
                    student = Students(**entry)
                    db.session.add(student)
                else:
                    student = Students.query.get(entry.get('roll_no'))
                    student.name = entry.get('name')
                    student.marks = entry.get('marks')
                    # add logic to update row if roll_no exists
            db.session.commit()
            return jsonify({'message': 'Excel file uploaded successfully'}), 200
    elif file.filename.endswith('.csv'): 
        df = pd.read_csv(file)
        df.columns = [col.lower() for col in df.columns]
        if not {'roll_no', 'name', 'marks'}.issubset(df.columns):
            return jsonify({'message': 'Incorrect Header format'}), 400
        try:
            df = df[['roll_no', 'name', 'marks']]
            df.dropna(inplace=True)
            m_data = students_schema.load(df.to_dict(orient='records'))
        # print(m_data)
        except ValidationError as errors:
            return jsonify({'message': 'Validation error', 'errors': errors}), 422

        roll_nos = {student.roll_no for student in Students.query.all()}

        for entry in m_data:
            if entry.get('roll_no') not in roll_nos:
                student = Students(**entry)
                db.session.add(student)
            else:
                student = Students.query.get(entry.get('roll_no'))
                student.name = entry.get('name')
                student.marks = entry.get('marks')
                # add logic to update row if roll_no exists
        db.session.commit()
        return jsonify({'message': 'CSV file uploaded successfully'}), 200
            # except Exception as e:
            #     return jsonify({'message': str(e)}), 500
    else:
        return jsonify({'message': 'Invalid file format'}), 400


def delete_single_record(rollno):
    record = Students.query.filter_by(roll_no=rollno).first()
    if not record:
        return ({'message': f'No record found with roll no {rollno}'}), 404
    else:
        db.session.delete(record)
        db.session.commit()
        return ({'message': f'successfully deleted the record with roll no {rollno}'}), 200

@app.route('/delete/<int:rollno>',methods=['DELETE'])
@login_required
def deleteRecord(rollno):
    message, status = delete_single_record(rollno)
    return jsonify(message), status

@app.route('/delete', methods={"DELETE"})
@login_required
def deleteRecords():
    record = request.get_json().get('rollno')
    message = {}
    for i, rollno in enumerate(record):
        x, s = delete_single_record(rollno)
        # if s == 404:
        #     return x
        # else:
        message[i] = x, s
    # print(message)
    return jsonify(message), 200


@app.route('/update/<int:rollno>', methods=['PUT'])
@login_required
def updateRecord(rollno):
    student = Students.query.get(rollno)
    if not student:
        return jsonify({'message': f'No record of roll_no: {rollno}'}), 404
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided in the request body'}), 400

    if 'name' not in data and 'marks' not in data:
        return jsonify({'message': 'name or marks fields are required'}), 400
    
    if 'name' in data:
        student.name = data.get('name')
    if 'marks' in data:
        student.marks = data.get('marks')
    
    db.session.commit()

    return jsonify({'message': f'{rollno} updated successfully'}), 200

if __name__ =='__main__':
    app.run(debug=True, host='0.0.0.0')