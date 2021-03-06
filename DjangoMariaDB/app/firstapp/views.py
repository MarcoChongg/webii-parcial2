# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

#def vista(request):
#    return render(request, 'clase.html', )

def vista(request):

    #https://docs.djangoproject.com/en/3.0/ref/templates/language/#templates
    return render(request, 'clase.html', {'title': "Bumblebee" , 'movies': Movie.objects.all()})


def vista2(request):

    #https://docs.djangoproject.com/en/3.0/ref/templates/language/#templates
    return render(request, 'dos.html', {'title': "Bumblebee" , 'movies': Movie.objects.all()})

def login(request):

    #VALIDATE METHOD
    if request.method == 'POST':

        #DECLARE RESPONSE
        responseData = {}

        #CHECK JSON STRUCTURE
        checkJsons = checkJson()
        check = checkJsons.isJson(request.body)
        if check == True:
            json_data = json.loads(request.body)
            attr_error = False
            attrErrorMsg = ""
        #CHECK JSON CONTENT
            if 'user' not in json_data:
                attr_error = True
                attrErrorMsg = "User is required"
            elif 'password' not in json_data:
                attr_error = True
                attrErrorMsg = "Password is required"
            if attr_error == True:
                responseData['result'] = 'error'
                responseData['message'] = attrErrorMsg
                return JsonResponse(responseData, status=401)
            else:
                responseData['result'] = 'sucess'
                responseData['message'] = ''
                #return JsonResponse(responseData, status=200)
                #CHECK IF USER EXISTS
                body = json.loads(request.body.decode('utf-8'))
                user = body.get("user")
                password = body.get("password")
                try:
                    currentuser = ApiUsers.objects.get(user=user)
                    responseData['result'] = 'success'
                    #return JsonResponse(responseData, status=200)
                except ApiUsers.DoesNotExist:
                    responseData['result'] = 'error'
                    responseData['message'] =  'The user does not exist or the password is incorrect'
                    return JsonResponse(responseData, status=401)

                #TAKE PASSWORD OF THE USER
                #currentuser = ApiUsers.objects.get(user=user)
                hashpass = currentuser.password

                #CHECK IF PASSWORD IS CORRECT
                checkpass = check_password(password,hashpass)
                if checkpass == True:
                    #responseData['result'] = 'success'
                    #responseData['message'] =  'Successfull user and pass'
                    #return JsonResponse(responseData, status=200)

                    #CHECK IF USER HAS API-KEY
                    if currentuser.api_key == None:
                        generateKey = ApiKey()
                        newApiKey = generateKey.generate_key_complex()
                        currentuser.api_key = newApiKey
                        currentuser.save()

                    #SUCCESSFULL LOGIN
                    responseData['result'] = 'sucess'
                    responseData['message'] = 'Valid Credentials'
                    responseData['userApiKey'] = currentuser.api_key
                    return JsonResponse(responseData, status=200)

                else:
                    responseData['result'] = 'error'
                    responseData['message'] =  'The user does not exist or the password is incorrect'
                    #RETURN RESPONSE
                    return JsonResponse(responseData, status=401)

        else:
            responseData['result'] = 'error'
            responseData['message'] = 'Invalid Json'
            return JsonResponse(responseData, status=400)

    else:
        responseData = {}
        responseData['result'] = 'error'
        responseData['message'] = 'Invalid Request'
        return JsonResponse(responseData, status=400)


def makepassword(request,password):
    hashPassword = make_password(password)
    responseData = {}
    responseData['password'] = hashPassword
    return JsonResponse(responseData, status=200)


def showmovielist(request):
    #VALIDATE METHOD
    if request.method == 'POST':

        #DECLARE RESPONSE
        responseData = {}

        #CHECK JSON STRUCTURE
        checkJsons = checkJson()
        check = checkJsons.isJson(request.body)
        if check == True:
            json_data = json.loads(request.body)
            attr_error = False
            attrErrorMsg = ""
        #CHECK JSON CONTENT
            apikey = request.headers["user-api-key"]
            if apikey == None:
                responseData['result'] = 'error'
                responseData['message'] =  'user-api-key is required'
                return JsonResponse(responseData, status=401)
            else:
                if 'user' not in json_data:
                    attr_error = True
                    attrErrorMsg = "User is required"
                elif 'password' not in json_data:
                    attr_error = True
                    attrErrorMsg = "Password is required"
                if attr_error == True:
                    responseData['result'] = 'error'
                    responseData['message'] = attrErrorMsg
                    return JsonResponse(responseData, status=401)
                else:
                    responseData['result'] = 'sucess'
                    responseData['message'] = ''
                    #CHECK IF USER EXISTS
                    body = json.loads(request.body.decode('utf-8'))
                    user = body.get("user")
                    password = body.get("password")
                    try:
                        currentuser = ApiUsers.objects.get(user=user)
                        responseData['result'] = 'success'
                        #return JsonResponse(responseData, status=200)
                    except ApiUsers.DoesNotExist:
                        responseData['result'] = 'error'
                        responseData['message'] =  'The user does not exist or the password is incorrect'
                        return JsonResponse(responseData, status=401)

                    #TAKE PASSWORD OF THE USER
                    #currentuser = ApiUsers.objects.get(user=user)
                    hashpass = currentuser.password

                    #CHECK IF PASSWORD IS CORRECT
                    checkpass = check_password(password,hashpass)
                    if checkpass == True:
                        #responseData['result'] = 'success'
                        #responseData['message'] =  'Successfull user and pass'
                        #return JsonResponse(responseData, status=200)

                        #CHECK API
                        if currentuser.api_key == apikey:
                            responseData = {}
                            responseData["movie"] = {}
                            cont = 0
                            for i in Movie.objects.all():
                                responseData["movie"][cont] = {}
                                responseData["movie"][cont]['id'] = i.movieid
                                responseData["movie"][cont]['title'] = i.movietitle
                                responseData["movie"][cont]['releaseDate'] = i.releasedate
                                responseData["movie"][cont]['imageUrl'] = i.imageurl
                                responseData["movie"][cont]['description'] = i.description
                                cont = cont + 1

                            responseData['result'] = 'success'
                            return JsonResponse(responseData, status = 200)
                        else:
                            responseData['result'] = 'error'
                            responseData['message'] =  'Invalid Api-key'
                            return JsonResponse(responseData, status = 401)

                    else:
                        responseData['result'] = 'error'
                        responseData['message'] =  'The user does not exist or the password is incorrect'
                        #RETURN RESPONSE
                        return JsonResponse(responseData, status=401)

        else:
            responseData['result'] = 'error'
            responseData['message'] = 'Invalid Json'
            return JsonResponse(responseData, status=400)

    else:
        responseData = {}
        responseData['result'] = 'error'
        responseData['message'] = 'Invalid Request'
        return JsonResponse(responseData, status=400)
