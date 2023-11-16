import os
from flask import Flask, jsonify, g, request
# from flask_pymongo import PyMongo
from bson import ObjectId, json_util
from pymongo import MongoClient 
from datetime import datetime

app = Flask(__name__)

# app.py
# app.py
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb+srv://root:rootravi7877@cluster0.vwzslkb.mongodb.net/?retryWrites=true&w=majority')


def get_db():
    if 'db' not in g:
        g.db = MongoClient(app.config['MONGO_URI'])
    return g.db

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





class JobPosting:
    def __init__(self, job_title, status='Open', start_date=None, end_date=None, hiring_manager=None, skill_sets=None, job_description=None):
        self.job_title = job_title
        self.status = status
        self.start_date = start_date
        self.end_date = end_date
        self.hiring_manager = hiring_manager
        self.skill_sets = skill_sets if skill_sets else []
        self.job_description = job_description

    def to_dict(self):
        return {
            'job_title': self.job_title,
            'status': self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'hiring_manager': self.hiring_manager,
            'skill_sets': [skill_set.to_dict() for skill_set in self.skill_sets],
            'job_description': self.job_description,
        }
class SkillSet:
    def __init__(self, name, description=None):
        self.name = name
        self.description = description

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
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










# job postion
@app.route('/create-job-posting', methods=['POST'])
def create_job_posting():
    data = request.get_json()

    if data:
        skill_sets_data = data.get('skill_sets', [])
        skill_sets = [SkillSet(name=skill['name'], description=skill.get('description')) for skill in skill_sets_data]

        job_posting_data = {
            'job_title': data.get('job_title'),
            'status': data.get('status', 'Open'),
            'start_date': data.get('start_date'),
            'end_date': data.get('end_date'),
            'hiring_manager': data.get('hiring_manager'),
            'skill_sets': [skill.to_dict() for skill in skill_sets],
            'job_description': data.get('job_description'),
        }

        db = get_db()
        db.linkme.job_postings.insert_one(job_posting_data)

        return jsonify({'message': 'Job Posting created successfully'}), 200

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/update-job-posting/<string:job_posting_id>', methods=['PUT'])
def update_job_posting(job_posting_id):
    data = request.get_json()

    if data:
        db = get_db()
        
        skill_sets_data = data.get('skill_sets', [])
        skill_sets = [SkillSet(name=skill['name'], description=skill.get('description')) for skill in skill_sets_data]

        result = db.linkme.job_postings.update_one(
            {'_id': ObjectId(job_posting_id)},
            {'$set': {
                'job_title': data.get('job_title'),
                'status': data.get('status', 'Open'),
                'start_date': data.get('start_date'),
                'end_date': data.get('end_date'),
                'hiring_manager': data.get('hiring_manager'),
                'skill_sets': [skill.to_dict() for skill in skill_sets],
                'job_description': data.get('job_description'),
            }}
        )

        if result.modified_count > 0:
            return jsonify({'message': 'Job Posting updated successfully'}), 200
        else:
            return jsonify({'error': 'Job Posting not found or not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400

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

