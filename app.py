import os
import bcrypt
from bson import json_util
from flask import Flask, jsonify, g, request, session, redirect, url_for
from bson import ObjectId, json_util
from pymongo import MongoClient 
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from job_posting.job_posting import JobPosting
from flask_bcrypt import Bcrypt
from flask_principal import Principal, RoleNeed, identity_changed, Identity
import openai
from user.user import User
from flask_cors import CORS




app = Flask(__name__)
CORS(app,
    origins=['http://localhost:3000', 'https://linkmebackend.onrender.com'],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True,
    expose_headers=["Content-Range", "X-Content-Range"])



login_manager = LoginManager(app)
principal = Principal(app)

app.config['JWT_SECRET_KEY'] = 'mySecreateKeyIsMaiKyuBatau'
jwt = JWTManager(app)




app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb+srv://root:rootravi7877@cluster0.vwzslkb.mongodb.net/?retryWrites=true&w=majority')
#Get database
def get_db():
    if 'db' not in g:
        g.db = MongoClient(app.config['MONGO_URI'])
    return g.db






openai.api_key = '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'

from pymongo import DESCENDING
# Function to get job recommendations from the database
def get_jobs_from_database(user_skills, user_experience_str):
    db = get_db()
    job_postings_collection = db["linkme"]["job_postings"]

    try:
        user_experience = int(user_experience_str)
    except ValueError:
        print("Invalid experience value, must be a numeric string")
        return []

    query = {
    "skill_sets": {"$elemMatch": {"$in": user_skills}},
    "experience": {"$lte": str(user_experience)}
    }



    cursor = job_postings_collection.find(query).sort([("experience", -1)]).limit(10)
    # print("list",list(cursor))



    jobs = list(cursor)

    

    return jobs



#Function to get recomandation for GanAi
@app.route('/recommend_jobs', methods=['POST'])
@jwt_required() 
def recommend_jobs():
    user_id = get_jwt_identity()
    user_skills = request.json.get('skill_sets', [])
    user_experience_str = request.json.get('experience', "0")

    try:
        user_experience = int(user_experience_str)
    except ValueError:
        return jsonify({'error': 'Invalid experience value, must be a numeric string'}), 400

    recommended_jobs = get_jobs_from_database(user_skills, user_experience)

    return jsonify({'recommendations': recommended_jobs}), 200








# Function to get job recommendations from the database
def get_users_from_database(user_skills, user_experience_str):
    db = get_db()
    job_postings_collection = db["linkme"]["users"]
    try:
        user_experience = int(user_experience_str)
    except ValueError:
        print("Invalid experience value, must be a numeric string")
        return []
    query = {
    "skills": {"$elemMatch": {"$in": user_skills}}
    }
    print("query", query)
    cursor = job_postings_collection.find(query)
    jobs = list(cursor)
    return jobs


@app.route('/recommend_users', methods=['POST'])
@jwt_required() 
def recommend_users():
    user_id = get_jwt_identity()  
    user_skills = request.json.get('skills', []) 
    user_experience_str = request.json.get('experience', "0")  

    try:
        user_experience = int(user_experience_str)
    except ValueError:
        return jsonify({'error': 'Invalid experience value, must be a numeric string'}), 400

    recommended_jobs = get_users_from_database(user_skills, user_experience)

    return json_util.dumps({'recommendations_users': recommended_jobs}), 200
















admin_role = RoleNeed('admin')
job_seeker_role = RoleNeed('job_seeker')

# Set up default roles for users
@principal.identity_loader
def load_identity():
    if current_user.is_authenticated:
        identity = Identity(current_user._id)
        if current_user.is_admin:
            identity.provides.add(admin_role)
        else:
            identity.provides.add(job_seeker_role)
        return identity







# job seekers
@app.route('/', methods=['GET'])
def get_data():
    db = get_db()
    job_seekers_data = list(db.linkme.users.find())
    job_postings_data = list(db.linkme.job_postings.find())
    applications_data = list(db.linkme.applications.find())

    return json_util.dumps({'users': job_seekers_data, 'job_postings': job_postings_data, 'applications': applications_data})


@app.before_request
def before_request():
    g.db = get_db()

# @app.route('/job_seeker/create', methods=['POST'])
# def create():
#     data = request.get_json()

#     if data:
#         job_seeker_data = {
#             'name': data.get('name'),
#             'status': data.get('status', False),
#             'skills': data.get('skills', []),
#             'experience': data.get('experience'),
#             'bio': data.get('bio'),
#             'availability': datetime.utcnow() if data.get('availability') else None
#         }

#         db = get_db()
#         db.linkme.job_seekers.insert_one(job_seeker_data)

#         return jsonify({'message': 'Job Seeker created successfully'}), 200

#     return jsonify({'error': 'Invalid data provided'}), 400

# @app.route('/update/<string:job_seeker_id>', methods=['PUT'])
# def update(job_seeker_id):
#     data = request.get_json()

#     if data:
#         db = get_db()
#         result = db.linkme.job_seekers.update_one(
#             {'_id': ObjectId(job_seeker_id)},
#             {'$set': {
#                 'name': data.get('name'),
#                 'status': data.get('status', False),
#                 'skills': data.get('skills', []),
#                 'experience': data.get('experience'),
#                 'bio': data.get('bio'),
#                 'availability': datetime.utcnow() if data.get('availability') else None
#             }}
#         )

#         if result.modified_count > 0:
#             return jsonify({'message': 'Job Seeker updated successfully'}), 200
#         else:
#             return jsonify({'error': 'Job Seeker not found or not modified'}), 404

#     return jsonify({'error': 'Invalid data provided'}), 400

# @app.route('/delete/<string:job_seeker_id>', methods=['DELETE'])
# def delete(job_seeker_id):
#     db = get_db()
#     result = db.linkme.job_seekers.delete_one({'_id': ObjectId(job_seeker_id)})

#     if result.deleted_count > 0:
#         return jsonify({'message': 'Job Seeker deleted successfully'}), 200
#     else:
#         return jsonify({'error': 'Job Seeker not found'}), 404








# job postion
@app.route('/jobpostings', methods=['GET'])
# @jwt_required() 
def get_job_postings():
    db = get_db()
    job_postings_data = list(db.linkme.job_postings.find())
    
    return json_util.dumps({'job_postings': job_postings_data}), 200
@app.route('/create_job_posting', methods=['POST'])
# @jwt_required() 
def create_job_posting():
    db = get_db()

    # Generate a new ObjectId
    new_job_id = ObjectId()

    # Get other fields from the request
    job_title = request.json['job_title']
    user_id = request.json['user_id']
    status = request.json['status']
    company = request.json['company']
    start_date = request.json['start_date']
    end_date = request.json['end_date']
    hiring_manager = request.json['hiring_manager']
    skill_sets = request.json['skill_sets']
    job_description = request.json['job_description']
    is_bookmarked = request.json['is_bookmarked']
    experience = request.json['experience']
    img = request.json['img']

    # Create a new JobPosting instance with the generated ObjectId
    new_job = JobPosting(
        _id=new_job_id,
        job_title=job_title,
        user_id=user_id,
        status=status,
        company=company,
        start_date=start_date,
        end_date=end_date,
        hiring_manager=hiring_manager,
        skill_sets=skill_sets,
        job_description=job_description,
        experience=experience,
        is_bookmarked=is_bookmarked,
        img=img,
    )

    # Insert the new job posting into the database
    db.linkme.job_postings.insert_one(new_job.to_dict())

    return jsonify(message="Job posting created successfully.")



@app.route('/get_job_posting/<string:job_id>', methods=['GET'])
# @jwt_required() 
def get_job_posting(job_id):
    db = get_db()

    try:
        # Convert the job_id to ObjectId
        job_id_obj = ObjectId(job_id)
    except:
        return jsonify(error="Invalid job ID format"), 400

    # print(f"Searching for job posting with _id: {job_id}")

    # Fetch the job posting from the database by ID
    job_posting = db.linkme.job_postings.find_one({"_id": job_id})

    if job_posting is None:
        # print("Job posting not found.")
        return jsonify(error="Job posting not found"), 404

    # Convert the ObjectId to a string in the job posting document
    job_posting['_id'] = str(job_posting['_id'])

    # print("Job posting found:", job_posting)

    return json_util.dumps(job_posting)




@app.route('/delete-job-posting/<string:job_posting_id>', methods=['DELETE'])
# @jwt_required() 
def delete_job_posting(job_posting_id):
    db = get_db()
    result = db.linkme.job_postings.delete_one({'_id': ObjectId(job_posting_id)})

    if result.deleted_count > 0:
        return jsonify({'message': 'Job Posting deleted successfully'}), 200
    else:
        return jsonify({'error': 'Job Posting not found'}), 404

@app.route('/users/bookmark-job/<string:user_id>/<string:job_posting_id>', methods=['PUT'])
# @jwt_required() 
def bookmark_job_by_user_id(user_id, job_posting_id):
    db = get_db()

    # Check if the user and job posting exist
    user = db.linkme.users.find_one({'_id': ObjectId(user_id)})
    job_posting = db.linkme.job_postings.find_one({'_id': ObjectId(job_posting_id)})

    if not user or not job_posting:
        return jsonify({'error': 'User or job posting not found'}), 404

    # Check if the user has already bookmarked the job posting
    is_bookmarked = user.get('is_bookmarked', [])

    if job_posting_id in is_bookmarked:
        return jsonify({'error': 'Job posting is already bookmarked by the user'}), 400

    # Update the user's bookmarked job postings
    is_bookmarked.append(job_posting_id)

    result = db.linkme.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'is_bookmarked': is_bookmarked}}
    )

    if result.modified_count > 0:
        return jsonify({'message': 'Job posting bookmarked successfully'}), 200
    else:
        return jsonify({'error': 'User not found or bookmark status not modified'}), 404



@app.route('/update_job_status/<job_id>', methods=['POST'])
# @jwt_required() 
def update_job_status_endpoint(job_id):
    try:
        # Get data from the request
        data = request.get_json()
        new_status = data.get('status')

        # Get the database connection
        db = get_db()

        # Selecting the collection
        job_postings_collection = db["linkme"]["job_postings"]

        # Updating the status for the specified job_id
        query = {"_id": job_id}
        update = {"$set": {"status": new_status}}

        result = job_postings_collection.update_one(query, update)

        if result.modified_count > 0:
            response = {"message": f"Status updated successfully for job {job_id}"}
        else:
            response = {"message": f"No job found with id {job_id}"}

    except Exception as e:
        response = {"error": f"Error updating status: {e}"}

    return jsonify(response)











# application
@app.route('/get_all_applications', methods=['GET'])
def get_all_applications():
    db = get_db()
    applications_data = list(db.linkme.applications.find())

    return json_util.dumps({'applications': applications_data}), 200


@app.route('/apply/<string:job_posting_id>/<string:job_seeker_id>', methods=['POST'])
def apply(job_posting_id, job_seeker_id):
    data = request.get_json()

    db = get_db()

    
    if not ObjectId.is_valid(job_seeker_id) or not ObjectId.is_valid(job_posting_id):
        return jsonify({'error': 'Invalid job_seeker_id or job_posting_id format'}), 400

    job_seeker = get_job_seeker(job_seeker_id)
    job_posting = get_job_posting(job_posting_id)

   
    if not job_seeker:
        return jsonify({'error': 'Job seeker or job posting not found'}), 404

    if not job_posting:
        return jsonify({'error': 'job posting not found'}), 404 
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



@app.route('/applications/<string:job_posting_id>', methods=['GET'])
def check_application(job_posting_id):
    # Get the user ID from the current_user object
    user_id = current_user._id

    # Query the database to check if the user has applied for the specified job
    db = get_db()
    application = db.linkme.applications.find_one({
        'job_seeker_id': user_id,
        'job_posting_id': job_posting_id
    })

    # Return a response indicating whether the user has applied
    if application:
        return jsonify({'applied': True}), 200
    else:
        return jsonify({'applied': False}), 200













# Secreat key to hash the password
app.config['SECRET_KEY'] = 'MySecreatKeyIsMaiNahiBataunga'

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_collection = db.linkme.users  # Adjust this based on your actual collection name
    return User.get_user_by_id(user_id, user_collection)

@app.route('/get_all_users', methods=['GET'])

def get_all_users():
    db = get_db()
    applications_data = list(db.linkme.users.find())

    return json_util.dumps({'users': applications_data}), 200


bcrypt = Bcrypt()
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if data:
        username = data.get('username')
        password = data.get('password')
        img = data.get('img')  # Add additional user details as needed
        fullName = data.get('fullName')
        description = data.get('description')
        status = data.get('status')
        contact_number = data.get('contact_number')
        is_active = data.get('is_active', True)
        is_admin = data.get('is_admin', False)
        job_seeker = data.get('job_seeker')
        is_bookmarked = data.get('is_bookmarked', False)

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
            'fullName': fullName,
            'description': description,
            'status': status,
            'is_active': is_active,
            'is_admin': is_admin,
            'contact_number': contact_number,
            'job_seeker': job_seeker,
            'is_bookmarked': is_bookmarked,
        }

        result = db.linkme.users.insert_one(user_data)
        _id = str(result.inserted_id)

        # Optionally, log in the user after registration
        new_user = User(_id, username, password, img=img, fullName=fullName, description=description, status=status, is_active=is_active, is_admin=is_admin, is_bookmarked=is_bookmarked,job_seeker=job_seeker, contact_number=contact_number)
        login_user(new_user)

        return jsonify({'message': 'User registered successfully', 'user_id': _id}), 200

    return jsonify({'error': 'Invalid data provided'}), 400



# Login route
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
                    is_admin=user_data.get('is_admin', False),  # Add other user attributes as needed
                )

                # Log in the user using Flask-Login
                login_user(user)

                # Set a custom expiration time (e.g., 7 days)
                expires_delta = timedelta(hours=3)

                # Generate an access token with custom expiration time
                access_token = create_access_token(
                    identity=str(user_data['_id']),
                    expires_delta=expires_delta
                )

                expires_in_seconds = expires_delta.total_seconds()
                
                return jsonify({
                    'id': user._id,
                    'message': 'Login successful',
                    'access_token': access_token,
                    'is_admin': user.is_admin,
                    'expires_in': expires_in_seconds,
                }), 200
            else:
                return jsonify({'error': 'Incorrect password'}), 401
        else:
            return jsonify({'error': 'User not found'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400



# Logout route
@app.route('/logout', methods=['GET'])
# @jwt_required() 
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200



@app.route('/users/<string:user_id>', methods=['GET'])
# @jwt_required() 
def get_user_by_id(user_id):
    db = get_db()
    user = db.linkme.users.find_one({'_id': ObjectId(user_id)})

    if user:
        return jsonify({'user': User(**user).to_dict()}), 200
    else:
        return jsonify({'error': 'User not found'}), 404

# Endpoint to update a user by ID
@app.route('/users/<string:user_id>', methods=['PUT'])
@jwt_required()
def update_user_by_id(user_id):
    data = request.get_json()


    if data:
        db = get_db()
        result = db.linkme.users.update_one(
    {'_id': ObjectId(user_id)},
    {'$set': {
        'username': data.get('username'),
        'img': data.get('img'),
        'fullName': data.get('fullName'),
        'description': data.get('description'),
        'status': data.get('status'),
        'email': data.get('email'),  # Add email field
        'job_seeker': data.get('job_seeker'),  # Add email field
        'is_active': data.get('is_active', True),
        'contact_number': data.get('contact_number'),
        'is_bookmarked': data.get('is_bookmarked'),
        'is_admin': data.get('is_admin', False),
        'skills': data.get('skills', [])  # Add skills field (assuming it's a list)
    }}
)

        if result.modified_count > 0:
            return jsonify({'message': 'User updated successfully'}), 200
        else:
            return jsonify({'error': 'User not found or not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/users/bookmarked/<string:user_id>', methods=['PUT'])
# @jwt_required()
def update_bookmark_user_by_id(user_id):
    data = request.get_json()

    if data:
        db = get_db()
        result = db.linkme.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'is_bookmarked': data.get('is_bookmarked')
            }}
        )

        if result.modified_count > 0:
            return jsonify({'message': 'User bookmark status updated successfully'}), 200
        else:
            return jsonify({'error': 'User not found or bookmark status not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400


@app.route('/update-password', methods=['PUT'])
# @jwt_required() 
def update_password():
    user_id = get_jwt_identity()
    data = request.get_json()

    if data:
        new_password = data.get('new_password')

        if not new_password:
            return jsonify({'error': 'New password is required'}), 400

        # Hash the new password using bcrypt
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Get the MongoDB client using the get_db function
        db = get_db()

        # Update the user's password in the database
        result = db.linkme.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'password': hashed_password}}
        )

        if result.modified_count > 0:
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            return jsonify({'error': 'User not found or password not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400




    
   






def get_job_seeker(job_seeker_id):
    db = get_db()
    # print(job_seeker_id)
    data = db.linkme.users.find_one({'_id': ObjectId(job_seeker_id)})
    # print(data)
    return data


def get_job_posting(job_posting_id):
    db = get_db()
    # print("Before query - job_posting_id:", job_posting_id)
    data = db.linkme.job_postings.find_one({'_id': job_posting_id})
    # print("After query - data:", data)
    return data


@app.teardown_appcontext
def teardown_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)

