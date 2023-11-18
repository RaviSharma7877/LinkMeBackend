# job_posting.py

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
