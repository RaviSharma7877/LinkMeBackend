import os
from flask import Flask, jsonify, g, request, session, redirect, url_for
from bson import ObjectId, json_util
from pymongo import MongoClient 
from datetime import datetime
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt

from user.user import User

app = Flask(__name__)
login_manager = LoginManager(app)

app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb+srv://root:rootravi7877@cluster0.vwzslkb.mongodb.net/?retryWrites=true&w=majority')
app.config['JWT_SECRET_KEY'] = 'mySecreateKeyIsMaiKyuBatau'  # Change this to a secret key of your choice
jwt = JWTManager(app)




def get_db():
    if 'db' not in g:
        g.db = MongoClient(app.config['MONGO_URI'])
    return g.db
















class User:
    def __init__(self, _id, username, password, img=None, name=None, desc=None, status=None, is_active=True):
        self._id = _id
        self.username = username
        self.password = password
        self.img = img
        self.name = name
        self.desc = desc
        self.status = status
        self.is_active = is_active

    def to_dict(self):
        return {
            'user_id': str(self._id) if self.user_id is not None else None,
            'username': self.username,
            'password': self.password,  # Note: Storing passwords in plaintext is not recommended in production.
            'img': self.img,
            'name': self.name,
            'desc': self.desc,
            'status': self.status,
            'is_active': self.is_active,
        }
        
        
    
    def _hash_password(self, password):
        if password is not None:
            if isinstance(password, str):  # Check if password is a string
                password_bytes = password.encode('utf-8')
                hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
                return hashed_password.decode('utf-8')  # Decode bytes to string before storing
            elif isinstance(password, bytes):  # Check if password is already in bytes
                raise ValueError("Password must be a string")
            else:
                raise ValueError("Password must be a string or bytes")
        else:
            return None

    def check_password(self, password):
        return check_password_hash(self.password, password) if self.password is not None else False

    def get_id(self):
        return str(self._id) if self._id is not None else None

    @property
    def is_authenticated(self):
        # Add your authentication logic here, e.g., return True if the user is authenticated
        return True

    @staticmethod
    def get_user_by_id(user_id, user_collection):
        user_data = user_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(
                _id=str(user_data['_id']),
                username=user_data['username'],
                password=user_data['password'],
                # Add other user attributes as needed
            )
        return None
    
    def __repr__(self):
        return f"User(username='{self.username}', status='{self.status}', is_active={self.is_active})"



class JobSeeker:
    def __init__(self, name, status=False, skills=None, experience=None, bio=None, availability=None):
        self.name = name
        self.status = status
        self.skills = skills if skills else []
        self.experience = experience
        self.bio = bio
        self.availability = availability
        self.applications = []

    def to_dict(self):
        return {
            'name': self.name,
            'status': self.status,
            'skills': self.skills,
            'experience': self.experience,
            'bio': self.bio,
            'availability': self.availability.isoformat() if self.availability else None,
        }




class JobPosting:
    def __init__(self, job_title, status='Open', start_date=None, end_date=None, hiring_manager=None, skill_sets=None, job_description=None):
        self.job_title = job_title
        self.status = status
        self.start_date = start_date
        self.end_date = end_date
        self.hiring_manager = hiring_manager
        self.skill_sets = skill_sets if skill_sets else []  # Assume skill_sets is a list of strings
        self.job_description = job_description

    def to_dict(self):
        return {
            'job_title': self.job_title,
            'status': self.status,
            'start_date': str(self.start_date) if self.start_date else None,
            'end_date': str(self.end_date) if self.end_date else None,
            'hiring_manager': self.hiring_manager,
            'skill_sets': self.skill_sets,
            'job_description': self.job_description,
        }


class Application:
    def __init__(self, job_seeker_id, job_posting_id, status='Pending', details=None):
        self.job_seeker_id = job_seeker_id
        self.job_posting_id = job_posting_id
        self.status = status
        self.details = details or {}

    def to_dict(self):
        return {
            'job_seeker_id': self.job_seeker_id,
            'job_posting_id': self.job_posting_id,
            'status': self.status,
            'details': self.details,
        }



























# job seekers

@app.route('/', methods=['GET'])
def get_data():
    db = get_db()
    job_seekers_data = list(db.linkme.job_seekers.find())
    job_postings_data = list(db.linkme.job_postings.find())
    applications_data = list(db.linkme.applications.find())

    return json_util.dumps({'job_seekers': job_seekers_data, 'job_postings': job_postings_data, 'applications': applications_data})


@app.before_request
def before_request():
    g.db = get_db()

@app.route('/job_seeker/create', methods=['POST'])
def create():
    data = request.get_json()

    if data:
        job_seeker_data = {
            'name': data.get('name'),
            'status': data.get('status', False),
            'skills': data.get('skills', []),
            'experience': data.get('experience'),
            'bio': data.get('bio'),
            'availability': datetime.utcnow() if data.get('availability') else None
        }

        db = get_db()
        db.linkme.job_seekers.insert_one(job_seeker_data)

        return jsonify({'message': 'Job Seeker created successfully'}), 200

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/update/<string:job_seeker_id>', methods=['PUT'])
def update(job_seeker_id):
    data = request.get_json()

    if data:
        db = get_db()
        result = db.linkme.job_seekers.update_one(
            {'_id': ObjectId(job_seeker_id)},
            {'$set': {
                'name': data.get('name'),
                'status': data.get('status', False),
                'skills': data.get('skills', []),
                'experience': data.get('experience'),
                'bio': data.get('bio'),
                'availability': datetime.utcnow() if data.get('availability') else None
            }}
        )

        if result.modified_count > 0:
            return jsonify({'message': 'Job Seeker updated successfully'}), 200
        else:
            return jsonify({'error': 'Job Seeker not found or not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/delete/<string:job_seeker_id>', methods=['DELETE'])
def delete(job_seeker_id):
    db = get_db()
    result = db.linkme.job_seekers.delete_one({'_id': ObjectId(job_seeker_id)})

    if result.deleted_count > 0:
        return jsonify({'message': 'Job Seeker deleted successfully'}), 200
    else:
        return jsonify({'error': 'Job Seeker not found'}), 404








# mongo = PyMongo(app)

# job postion
@app.route('/create_job_posting', methods=['POST'])
def create_job_posting():
    db = get_db()
    job_title = request.json['job_title']
    status = request.json['status']
    start_date = request.json.get('start_date', None)
    end_date = request.json.get('end_date', None)
    hiring_manager = request.json['hiring_manager']
    skill_sets = request.json['skill_sets']
    job_description = request.json['job_description']

    new_job = JobPosting(job_title, status, start_date, end_date, hiring_manager, skill_sets, job_description)

    # Insert the new job posting into the database
    # (Replace 'db' with your actual database connection)
    db.linkme.job_postings.insert_one(new_job.to_dict())

    return jsonify(message="Job posting created successfully.")

# @app.route('/update-job-posting/<string:job_posting_id>', methods=['PUT'])
# def update_job_posting(job_posting_id):
#     data = request.get_json()

#     if data:
#         db = get_db()
        
#         skill_sets_data = data.get('skill_sets', [])
#         skill_sets = [SkillSet(name=skill['name'], description=skill.get('description')) for skill in skill_sets_data]

#         result = db.linkme.job_postings.update_one(
#             {'_id': ObjectId(job_posting_id)},
#             {'$set': {
#                 'job_title': data.get('job_title'),
#                 'status': data.get('status', 'Open'),
#                 'start_date': data.get('start_date'),
#                 'end_date': data.get('end_date'),
#                 'hiring_manager': data.get('hiring_manager'),
#                 'skill_sets': [skill.to_dict() for skill in skill_sets],
#                 'job_description': data.get('job_description'),
#             }}
#         )

#         if result.modified_count > 0:
#             return jsonify({'message': 'Job Posting updated successfully'}), 200
#         else:
#             return jsonify({'error': 'Job Posting not found or not modified'}), 404

#     return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/delete-job-posting/<string:job_posting_id>', methods=['DELETE'])
def delete_job_posting(job_posting_id):
    db = get_db()
    result = db.linkme.job_postings.delete_one({'_id': ObjectId(job_posting_id)})

    if result.deleted_count > 0:
        return jsonify({'message': 'Job Posting deleted successfully'}), 200
    else:
        return jsonify({'error': 'Job Posting not found'}), 404













# application
@app.route('/apply/<string:job_posting_id>/<string:job_seeker_id>', methods=['POST'])
def apply(job_posting_id, job_seeker_id):
    data = request.get_json()

    db = get_db()

    
    if not ObjectId.is_valid(job_seeker_id) or not ObjectId.is_valid(job_posting_id):
        return jsonify({'error': 'Invalid job_seeker_id or job_posting_id format'}), 400

    job_seeker = get_job_seeker(job_seeker_id)
    job_posting = get_job_posting(job_posting_id)

   
    if not job_seeker or not job_posting:
        return jsonify({'error': 'Job seeker or job posting not found'}), 404

    if data:
        application_data = {
            'job_seeker_id': job_seeker_id,
            'job_posting_id': job_posting_id,
            'status': 'Pending',
            'details': data.get('details', {}),
        }

        result = db.linkme.applications.insert_one(application_data)
        application_id = str(result.inserted_id)

        
        db.linkme.job_seekers.update_one(
            {'_id': ObjectId(job_seeker_id)},
            {'$push': {'applications': application_id}}
        )
        db.linkme.job_postings.update_one(
            {'_id': ObjectId(job_posting_id)},
            {'$push': {'applications': application_id}}
        )

        return jsonify({'message': 'Application submitted successfully', 'application_id': application_id}), 200

    return jsonify({'error': 'Invalid data provided'}), 400


@app.route('/update-application-status/<string:application_id>', methods=['PUT'])
def update_application_status(application_id):
    data = request.get_json()

    if data:
        db = get_db()
        result = db.linkme.applications.update_one(
            {'_id': ObjectId(application_id)},
            {'$set': {'status': data.get('status')}}
        )

        if result.modified_count > 0:
            return jsonify({'message': 'Application status updated successfully'}), 200
        else:
            return jsonify({'error': 'Application not found or not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/delete-application/<string:application_id>', methods=['DELETE'])
def delete_application(application_id):
    db = get_db()
    
    
    application = db.linkme.applications.find_one({'_id': ObjectId(application_id)})
    job_seeker_id = application['job_seeker_id']
    job_posting_id = application['job_posting_id']

    
    db.linkme.job_seekers.update_one(
        {'_id': ObjectId(job_seeker_id)},
        {'$pull': {'applications': application_id}}
    )
    db.linkme.job_postings.update_one(
        {'_id': ObjectId(job_posting_id)},
        {'$pull': {'applications': application_id}}
    )

    
    result = db.linkme.applications.delete_one({'_id': ObjectId(application_id)})

    if result.deleted_count > 0:
        return jsonify({'message': 'Application deleted successfully'}), 200
    else:
        return jsonify({'error': 'Application not found or not deleted'}), 404



@app.route('/applications', methods=['GET'])
@login_required
def get_applications():
    # Get the user ID from the current_user object
    user_id = current_user._id

    # Query the database to retrieve applications for the logged-in user
    db = get_db()
    applications = db.linkme.applications.find({'user_id': user_id})

    # Convert MongoDB cursor to a list of dictionaries
    application_list = [app.to_dict() for app in applications]

    # Return the list of applications as JSON
    return jsonify({'applications': application_list}), 200














app.config['SECRET_KEY'] = 'MySecreatKeyIsMaiNahiBataunga'


@login_manager.user_loader
def load_user(user_id):
    # Implement the load_user function as per your User class
    return User.get_user_by_id(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if data:
        username = data.get('username')
        password = data.get('password')

        db = get_db()
        user_data = db.linkme.users.find_one({'username': username})

        if user_data:
            stored_password = user_data['password']

            # Check the password using check_password_hash
            if check_password_hash(stored_password, password):
                # Create an instance of the User class
                user = User(
                    _id=str(user_data['_id']),
                    username=user_data['username'],
                    password=user_data['password'],
                    # Add other user attributes as needed
                )

                # Log in the user using Flask-Login
                login_user(user)

                # Generate an access token
                access_token = create_access_token(identity=str(user_data['_id']))

                return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
            else:
                return jsonify({'error': 'Incorrect password'}), 401
        else:
            return jsonify({'error': 'User not found'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    return User.get_user_by_id(user_id, db.linkme.users)



@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

# Protected route example
@app.route('/protected', methods=['GET'])
@login_required
def protected():
    return jsonify({'message': f'You are logged in as {current_user.username}'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if data:
        username = data.get('username')
        password = data.get('password')
        img = data.get('img')  # Add additional user details as needed
        name = data.get('name')
        desc = data.get('desc')
        status = data.get('status')
        is_active = data.get('is_active', True)

        db = get_db()

        # Check if the username is already taken
        existing_user = db.linkme.users.find_one({'username': username})
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400

        # Hash the password using generate_password_hash
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user and save details in the database
        user_data = {
            'username': username,
            'password': hashed_password,
            'img': img,  # Add additional user details as needed
            'name': name,
            'desc': desc,
            'status': status,
            'is_active': is_active,
        }

        result = db.linkme.users.insert_one(user_data)
        _id = str(result.inserted_id)

        # Optionally, log in the user after registration
        new_user = User(_id, username, password, img=img, name=name, desc=desc, status=status, is_active=is_active)
        login_user(new_user)

        return jsonify({'message': 'User registered successfully', 'user_id': _id}), 200

    return jsonify({'error': 'Invalid data provided'}), 400


















def get_job_seeker(job_seeker_id):
    db = get_db()
    return db.linkme.job_seekers.find_one({'_id': ObjectId(job_seeker_id)})

def get_job_posting(job_posting_id):
    db = get_db()
    return db.linkme.job_postings.find_one({'_id': ObjectId(job_posting_id)})


@app.teardown_appcontext
def teardown_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)

