# flask-task

Healthcheck: 
curl localhost:8080/

Get all users:
curl localhost:8080/users

Register a new user:
curl -X POST -H "Content-Type: application/json" -d '{"first_name": "Max", "last_name": "Mustermann", "email": "test@web.de", "profession": "Pfleger", "password": "test123"}' localhost:8080/register

Log in:
curl -X POST -H "Content-Type: application/json" -d '{"email": "test@web.de", "password": "test123"}' localhost:8080/login

Get user:
curl -X GET -H "Content-Type: application/json" localhost:8080/user  -H "Authorization: Bearer $JWT"

Update user:
curl -X PUT -H "Content-Type: application/json" -d '{"first_name": "Max", "last_name": "Mustermann", "email": "test2@web.de", "profession": "Pfleger", "password": "test123"}' localhost:8080/user -H "Authorization: Bearer $JWT"

Delete user:
curl -X DELETE -H "Content-Type: application/json" localhost:8080/user  -H "Authorization: Bearer $JWT"
