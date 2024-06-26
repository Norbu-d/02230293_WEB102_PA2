```
npm install
npm run dev
```

```
open http://localhost:3000
```
 The code provided sets up a backend server based on the Hono framework, which also interacts with Prisma and the JWT for purposes of authentication. 

Hono Framework: The Hono application is a web framework used for developing HTTP servers and APIs for creating the specified application. The app imports Hono and then creates an instance of the Hono and sets up the middlewares and routing.

CORS Middleware: It uses the cors middleware that allows the server to accept and handle client requests from different origins.

Prisma Client: To map data with the database, Prisma is used which is an ORM. This section also involves the instantiation of the Prisma client to facilitate the operations on the database.

JWT Middleware: Since the jwt middleware is used to protect routes with /protected/* prefix, these routes cannot be accessed without providing valid tokens. These routes are authenticated by validating the JWT tokens from this middleware.

## User Registration Endpoint (/register):

Accepts in the request body: email, username, and password that the user sent during registration.
Stores the password into the database by hashing it using bcrypt at a cost factor of 4.
Inserts a record into the database for user creation and saves the hashed password.
Works with unique constraint violations (i. e. , if email is already taken); it does so due to catching specific Prisma errors and returning the appropriate message.
User Login Endpoint (/login):

Accepts two parameters: login (string, email) and password (string, password) in the request body json section.
Retrieves detail information of the user from the database based on email address entered by the user.
To ensure that the password is securely stored, bcrypt is used to verify the password.
If credentials are true, it creates a JWT token with a payload that has the following parameters User ID, expiration time, 60 minutes.
If the authentication is authorized, then the function returns a JSON web token that is placed in the response field, otherwise, it returns the error message because the given credentials were not valid.
Security and Error Handling:

For authentication JWT has been employed in order to ensure that only authorized users, are given access to resources that are restricted.
Handling of errors is done with the use of HTTP exceptions by providing appropriate messages such as invalid credentials and unique constraint errors.

## CRUD function 

Read User Profile (GET /protected/profile):Read User Profile (GET /protected/profile):

To create JWT to authenticate the user, then get the user ID from the token.
It retrieves the profile of the current connected user from the database by using the Prisma.
It takes the ID , email, and username of the user and response with the ID, email, and username of the user if the user is in the database otherwise it returns the message “User not found” in the Kwargs with status code of 404.
Update User Profile (PUT /protected/profile):Update User Profile (PUT /protected/profile):

Checks whether a user is logged in and obtains the user ID from the JWT token.
Gets the new new-email set from the request body and gets the new new-username set from the request body.
Stores the details in the Prisma database, with the user’s profile being updated.
Returns a success message with the updated user profile if all the operations run successfully.
Delete User Profile (DELETE /protected/profile):Delete User Profile (DELETE /protected/profile):

Verifies the user and conducts the user ID extraction from the JWT token.
Uses Prisma to clear out the user’s data from the database or profile data as specifically referred to.
Produces back a success message after the deletion is successful.
Handles general server errors.
#   0 2 2 3 0 2 9 3 _ W E B 1 0 2 _ P A 2  
 