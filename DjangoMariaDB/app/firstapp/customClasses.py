import json
from django.http import JsonResponse
import string
import secrets
import random

class checkJson():

    def __init__(self):

        return None
    def isJson(self,myjson):
        try:
            json_object = json.loads(myjson)
        except ValueError as e:
            response_data = {}
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid Json'
            return response_data
        return True

class ApiKey():

    ApiLength = 32
    ApiLengthC = 64
    def __init__(self):
        return None

    def check(self,request):
        try:
            apiKey = request.headers["user-api-key"]
        except KeyError:
            response_data = {}
            response_data['result'] = 'error'
            response_data['message'] = 'user-api-key is required'
            return response_data
        return True

    def generate_key_simple(self):
        return secrets.token_hex(self.ApiLength)

    def generate_key_complex(self):
        char_set = string.ascii_letters + string.punctuation
        urand = random.SystemRandom()
        return ''.join([urand.choice(char_set) for _ in range(self.ApiLengthC)])
