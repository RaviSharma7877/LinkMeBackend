from flask import Flask, jsonify, g, request
from flask_mysqldb import MySQL
from datetime import datetime

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ravi@123'
app.config['MYSQL_DB'] = 'linkme'

mysql = MySQL(app)

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
    cur = mysql.connection.cursor()

    # Assuming you have tables named 'job_seekers', 'job_postings', 'applications'
    cur.execute("SELECT * FROM job_seekers")
    job_seekers_data = cur.fetchall()

    cur.execute("SELECT * FROM job_postings")
    job_postings_data = cur.fetchall()

    cur.execute("SELECT * FROM applications")
    applications_data = cur.fetchall()

    cur.close()

    return jsonify({'job_seekers': job_seekers_data, 'job_postings': job_postings_data, 'applications': applications_data})

@app.before_request
def before_request():
    g.db = mysql.connection

@app.route('/job_seeker/create', methods=['POST'])
def create():
    data = request.get_json()

    if data:
        cur = g.db.cursor()

        job_seeker_data = {
            'name': data.get('name'),
            'status': data.get('status', False),
            'skills': data.get('skills', []),
            'experience': data.get('experience'),
            'bio': data.get('bio'),
            'availability': datetime.utcnow() if data.get('availability') else None
        }

        cur.execute("INSERT INTO job_seekers (name, status, skills, experience, bio, availability) VALUES (%s, %s, %s, %s, %s, %s)",
                    (job_seeker_data['name'], job_seeker_data['status'], job_seeker_data['skills'], job_seeker_data['experience'],
                     job_seeker_data['bio'], job_seeker_data['availability']))

        g.db.commit()
        cur.close()

        return jsonify({'message': 'Job Seeker created successfully'}), 200

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/update/<string:job_seeker_id>', methods=['PUT'])
def update(job_seeker_id):
    data = request.get_json()

    if data:
        cur = g.db.cursor()
        cur.execute("UPDATE job_seekers SET name=%s, status=%s, skills=%s, experience=%s, bio=%s, availability=%s WHERE id=%s",
                    (data.get('name'), data.get('status', False), data.get('skills', []), data.get('experience'),
                     data.get('bio'), datetime.utcnow() if data.get('availability') else None, job_seeker_id))

        g.db.commit()
        cur.close()

        if cur.rowcount > 0:
            return jsonify({'message': 'Job Seeker updated successfully'}), 200
        else:
            return jsonify({'error': 'Job Seeker not found or not modified'}), 404

    return jsonify({'error': 'Invalid data provided'}), 400

@app.route('/delete/<string:job_seeker_id>', methods=['DELETE'])
def delete(job_seeker_id):
    cur = g.db.cursor()
    cur.execute("DELETE FROM job_seekers WHERE id=%s", (job_seeker_id,))
    g.db.commit()
    cur.close()

    if cur.rowcount > 0:
        return jsonify({'message': 'Job Seeker deleted successfully'}), 200
    else:
        return jsonify({'error': 'Job Seeker not found'}), 404

# ... Rest of your code ...

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
