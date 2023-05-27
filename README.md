# Old School Service

This service is an online learning platform where users can register, login, create a profile, upload courses, and upload grades.

## Vulnerabilities

1. **Mass Assignment**: During profile creation/update, the application is susceptible to mass assignment vulnerability. While updating user profile details, an attacker can add extra parameters (like is_admin) in the POST request, escalating their privileges.

2. **XML External Entity (XXE) Injection**: Users upload course data in the form of XML files. The application does not properly handle XML input which allows an attacker to to carry out LFI attacks where the player can read local files from the server.

3. **Twig Template Injection**: The application uses the Twig templating engine to render the 'about me' section on user profiles. Users can inject Twig templates in their 'about me' section, leading to template injection vulnerability. This also can be used to gain LFI.


## Flag Stores

1. **Flag Store 1**: Each user has a flag in the database which can be retrieved by exploiting the Mass Assignment vulnerability.

1. **Flag Store 2**: Another set of flags are stored as separate files on the server. These can be accessed by exploiting the Twig Template Injection vulnerability in the 'about me' section of a user's profile or leveraging the XXE to obtain LFI.
