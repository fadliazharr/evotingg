from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import pymongo
import json
import logging
import bcrypt
from bson import Binary, ObjectId
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
import numpy as np
import base64

# Initialize MongoDB client
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["eVoting"]

# Create a logger object
logger = logging.getLogger(__name__)

# File paths for keys and context
context_file = "context.ctx"
public_key_file = "public_key.pk"
secret_key_file = "secret_key.sk"

# Initialize Pyfhel for homomorphic encryption
HE = Pyfhel()
if not (default_storage.exists(context_file) and default_storage.exists(public_key_file) and default_storage.exists(secret_key_file)):
    HE.contextGen(scheme='bfv', n=2**14, t_bits=20)
    HE.keyGen()
    HE.save_context(context_file)
    HE.save_public_key(public_key_file)
    HE.save_secret_key(secret_key_file)
else:
    HE.load_context(context_file)
    HE.load_public_key(public_key_file)
    HE.load_secret_key(secret_key_file)

@method_decorator(csrf_exempt, name='dispatch')
class RegisterVoter(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            is_admin = data.get('is_admin', False)
            logger.info(f"Received data: {data}")

            if not username or not email or not password:
                return JsonResponse({'error': 'Missing fields'}, status=400)

            if db.users.find_one({'username': username}):
                return JsonResponse({'error': 'Username already exists'}, status=400)

            if db.users.find_one({'email': email}):
                return JsonResponse({'error': 'Email already exists'}, status=400)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            db.users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'is_active': True,
                'is_admin': is_admin
            })

            return JsonResponse({'message': 'User created successfully'}, status=201)
        except Exception as e:
            logger.error(f"User creation error: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'User creation failed', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            logger.info(f"Attempting login for user: {username}")

            user = db.users.find_one({'username': username})
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                return JsonResponse({
                    'message': 'Login successful',
                    'is_admin': user.get('is_admin', False),
                    'voter_id': str(user['_id'])  # Include voter_id in the response
                }, status=200)
            else:
                logger.warning("Invalid credentials")
                return JsonResponse({'error': 'Invalid credentials'}, status=400)
        except Exception as e:
            logger.error(f"Error during login: {e}", exc_info=True)
            return JsonResponse({'error': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class CreateElection(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            name = data.get('name')
            start_date = data.get('start_date')
            finish_date = data.get('finish_date')
            result_recap = data.get('result_recap')

            if not all([name, start_date, finish_date, result_recap]):
                return JsonResponse({'error': 'All fields are required'}, status=400)

            election = {
                'name': name,
                'start_date': start_date,
                'finish_date': finish_date,
                'is_empty_candidate': False,
                'total_candidate': 0,
                'result_recap': result_recap,
                'total_voter': 0,
                'voted_voter': 0,
                'id_agenda': ''
            }

            db.elections.insert_one(election)

            return JsonResponse({'message': 'Election created successfully'}, status=201)
        except Exception as e:
            logger.error(f"Error creating election: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Election creation failed', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class GetElections(View):
    def get(self, request):
        try:
            elections = list(db.elections.find({}, {'name': 1, 'start_date': 1, 'finish_date': 1, 'result_recap': 1}))
            for election in elections:
                election['_id'] = str(election['_id'])  # Convert ObjectId to string
            return JsonResponse({'elections': elections}, status=200)
        except Exception as e:
            logger.error(f"Error getting elections: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to get elections', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class DeleteElection(View):
    def delete(self, request, election_id):
        try:
            result = db.elections.delete_one({'_id': ObjectId(election_id)})  # Use ObjectId from bson
            if result.deleted_count > 0:
                return JsonResponse({'message': 'Election deleted successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Election not found'}, status=404)
        except Exception as e:
            logger.error(f"Error deleting election: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to delete election', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class Results(View):
    def get(self, request):
        try:
            votes = list(db.votes.find({}, {'_id': 0, 'vote': 1}))
            return JsonResponse({'votes': votes}, status=200)
        except Exception as e:
            logger.error(f"Error getting results: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to get results', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class GetCandidates(View):
    def get(self, request):
        try:
            candidates = list(db.candidates.find({}, {'name': 1, 'candidate_number': 1, 'description': 1, 'slogan': 1, 'email': 1}))
            for candidate in candidates:
                candidate['_id'] = str(candidate['_id'])  # Convert ObjectId to string
            return JsonResponse({'candidates': candidates}, status=200)
        except Exception as e:
            logger.error(f"Error getting candidates: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to get candidates', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class AssignCandidate(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            candidate_id = data.get('candidate_id')
            election_id = data.get('election_id')

            if not candidate_id or not election_id:
                return JsonResponse({'error': 'Missing candidate_id or election_id'}, status=400)

            db.elections.update_one(
                {'_id': ObjectId(election_id)},
                {'$addToSet': {'candidates': candidate_id}}
            )

            return JsonResponse({'message': 'Candidate assigned to election successfully'}, status=200)
        except Exception as e:
            logger.error(f"Error assigning candidate: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to assign candidate', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class RegisterCandidate(View):
    def post(self, request):
        try:
            data = request.POST
            files = request.FILES

            logger.info(f"Received data: {data}")
            logger.info(f"Received files: {files}")

            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            candidate_number = data.get('candidate_number')
            description = data.get('description', '')  # Provide default empty string
            slogan = data.get('slogan', '')  # Provide default empty string
            slogan_voice = files.get('slogan_voice')
            photo = files.get('photo')
            video = files.get('video')

            if not name or not email or not password or not candidate_number:
                return JsonResponse({'error': 'Missing fields'}, status=400)

            if db.candidates.find_one({'email': email}):
                return JsonResponse({'error': 'Email already exists'}, status=400)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            candidate_data = {
                'name': name,
                'email': email,
                'password': hashed_password,
                'candidate_number': candidate_number,
                'description': description,
                'slogan': slogan
            }

            if slogan_voice:
                slogan_voice_name = default_storage.save(f"slogan_voices/{slogan_voice.name}", ContentFile(slogan_voice.read()))
                candidate_data['slogan_voice'] = slogan_voice_name

            if photo:
                photo_name = default_storage.save(f"photos/{photo.name}", ContentFile(photo.read()))
                candidate_data['photo'] = photo_name

            if video:
                video_name = default_storage.save(f"videos/{video.name}", ContentFile(video.read()))
                candidate_data['video'] = video_name

            db.candidates.insert_one(candidate_data)

            return JsonResponse({'message': 'Candidate registered successfully'}, status=201)
        except Exception as e:
            logger.error(f"Error registering candidate: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Candidate registration failed', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class LoginCandidate(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            name = data.get('name')
            password = data.get('password')
            logger.info(f"Attempting login for candidate: {name}")

            candidate = db.candidates.find_one({'name': name})
            if candidate:
                stored_password = candidate['password']
                logger.debug(f"Stored password (hashed): {stored_password}")

                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    return JsonResponse({
                        'message': 'Login successful',
                        'candidate_id': str(candidate['_id']),  # Include candidate_id in the response
                        'candidate_number': candidate.get('candidate_number')
                    }, status=200)
                else:
                    logger.warning("Invalid credentials")
                    return JsonResponse({'error': 'Invalid credentials'}, status=400)
            else:
                logger.warning("Invalid name")
                return JsonResponse({'error': 'Invalid name'}, status=400)
        except Exception as e:
            logger.error(f"Error during candidate login: {e}", exc_info=True)
            return JsonResponse({'error': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class GetCandidatesByElection(View):
    def get(self, request, election_id):
        try:
            election = db.elections.find_one({'_id': ObjectId(election_id)}, {'candidates': 1})
            if not election:
                return JsonResponse({'error': 'Election not found'}, status=404)

            candidate_ids = election.get('candidates', [])
            candidates = list(db.candidates.find({'_id': {'$in': [ObjectId(cid) for cid in candidate_ids]}}, {'name': 1, 'candidate_number': 1, 'description': 1, 'slogan': 1, 'email': 1}))
            for candidate in candidates:
                candidate['_id'] = str(candidate['_id'])  # Convert ObjectId to string

            return JsonResponse({'candidates': candidates}, status=200)
        except Exception as e:
            logger.error(f"Error getting candidates by election: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to get candidates by election', 'details': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class Vote(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            voter_id = data.get('voter_id')
            election_id = data.get('election_id')
            candidate_id = data.get('candidate_id')

            logger.info(f"Received vote data: voter_id={voter_id}, election_id={election_id}, candidate_id={candidate_id}")

            if not all([voter_id, election_id, candidate_id]):
                logger.error("Missing fields in vote data")
                return JsonResponse({'error': 'Missing fields'}, status=400)

            # Check if the voter has already voted in this election
            if db.votes.find_one({'voter_id': voter_id, 'election_id': election_id}):
                logger.error(f"Voter {voter_id} has already voted in election {election_id}")
                return JsonResponse({'error': 'You have already voted in this election'}, status=400)

            # Convert candidate_id to a byte array
            candidate_id_bytes = ObjectId(candidate_id).binary
            logger.info(f"Candidate ID bytes: {candidate_id_bytes}")

            # Encrypt the candidate_id
            candidate_id_array = np.frombuffer(candidate_id_bytes, dtype=np.uint8).astype(np.int64)
            logger.info(f"Candidate ID array: {candidate_id_array}")
            candidate_id_ptxt = HE.encodeInt(candidate_id_array)
            encrypted_vote = HE.encrypt(candidate_id_ptxt)
            encrypted_vote_bytes = encrypted_vote.to_bytes()
            encrypted_vote_base64 = base64.b64encode(encrypted_vote_bytes).decode('utf-8')
            logger.info(f"Encrypted vote to base64: {encrypted_vote_base64}")

            # Create a composite key for uniqueness
            vote_id = f"{voter_id}_{election_id}"

            # Record the vote in the `voting_encryptedvote` collection
            db.voting_encryptedvote.insert_one({
                '_id': vote_id,
                'voter_id': voter_id,
                'election_id': election_id,
                'encrypted_vote': encrypted_vote_base64  # Store encrypted vote as base64 string
            })

            # Record the vote in the `votes` collection for tracking
            db.votes.insert_one({
                'voter_id': voter_id,
                'election_id': election_id,
                'candidate_id': candidate_id
            })

            # Update the voted_voter count in the election
            db.elections.update_one({'_id': ObjectId(election_id)}, {'$inc': {'voted_voter': 1}})

            logger.info(f"Vote recorded: voter_id={voter_id}, election_id={election_id}, candidate_id={candidate_id}")
            return JsonResponse({'message': 'Vote cast successfully'}, status=200)
        except pymongo.errors.DuplicateKeyError as e:
            logger.error(f"Duplicate key error during vote casting: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Duplicate vote error', 'details': str(e)}, status=400)
        except Exception as e:
            logger.error(f"Error casting vote: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to cast vote', 'details': str(e)}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class ElectionResultsView(View):
    def get(self, request, election_id):
        try:
            # Get all votes for the specified election from the `voting_encryptedvote` collection
            votes = list(db.voting_encryptedvote.find({'election_id': election_id}))

            # Initialize result counter
            results = {}

            for vote in votes:
                encrypted_vote_base64 = vote.get('encrypted_vote')
                if not encrypted_vote_base64:
                    logger.error("No encrypted_vote found in vote")
                    continue

                logger.debug(f"Processing encrypted vote base64: {encrypted_vote_base64}")

                try:
                    # Decode the base64 encoded encrypted vote
                    encrypted_vote_bytes = base64.b64decode(encrypted_vote_base64)
                    logger.debug(f"Encrypted vote bytes: {encrypted_vote_bytes}")

                    # Initialize PyCtxt with bytestring
                    encrypted_vote = PyCtxt(pyfhel=HE, bytestring=encrypted_vote_bytes)
                    
                    # Decrypt the vote
                    decrypted_candidate_id = HE.decrypt(encrypted_vote)
                    logger.debug(f"Decrypted candidate ID: {decrypted_candidate_id}")

                    # Convert decrypted candidate ID to integer
                    decrypted_candidate_id_int = int(decrypted_candidate_id[0])

                    # Ensure the integer is positive
                    if decrypted_candidate_id_int < 0:
                        decrypted_candidate_id_int += 2**64

                    # Convert integer to hex string
                    candidate_id_hex = format(decrypted_candidate_id_int, 'x').zfill(24)
                    logger.debug(f"Candidate ID hex: {candidate_id_hex}")

                    # Ensure the hex string is valid ObjectId
                    if len(candidate_id_hex) == 24:
                        candidate_id = ObjectId(candidate_id_hex)
                    else:
                        raise ValueError("Invalid ObjectId format")

                except Exception as e:
                    logger.error(f"Error during decryption or conversion: {str(e)}")
                    candidate_id = None

                if candidate_id:
                    candidate_id_str = str(candidate_id)
                    if candidate_id_str in results:
                        results[candidate_id_str] += 1
                    else:
                        results[candidate_id_str] = 1

            # Get candidate details
            candidates = db.candidates.find({'_id': {'$in': [ObjectId(cid) for cid in results.keys()]}})
            candidates_dict = {str(candidate['_id']): candidate['name'] for candidate in candidates}

            # Log candidate dictionary for debugging
            logger.debug(f"Candidates dict: {candidates_dict}")

            # Create results with candidate names
            formatted_results = []
            for cid, count in results.items():
                if cid in candidates_dict:
                    formatted_results.append({'candidate_id': cid, 'candidate_name': candidates_dict[cid], 'votes': count})
                else:
                    logger.error(f"Candidate ID {cid} not found in candidates_dict")

            return JsonResponse({'results': formatted_results}, status=200)
        except Exception as e:
            logger.error(f"Error getting election results: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Failed to get election results', 'details': str(e)}, status=400)
