# Oldschool

## How the Service Works
This service is an online learning platform where users can register, login, create a profile, upload courses, and join courses. Once a user creates a course, the user automatically becomes admin of the course. The courses can be private or public and course admins can view the list of other users enrolled in the same course. They can also see the profile of the enrolled users.

This service uses a PHP backend with a MySQL database, and the front-end is built using the Twig templating engine.

## Vulnerabilities

1. **Mass Assignment**: During profile update, the application is susceptible to mass assignment vulnerability. While updating user profile details, an attacker can add extra parameters (like admin_of) in the POST request.

2. **XML External Entity (XXE) Injection**: Users upload course data in the form of XML files. The application does not properly handle XML input which allows an attacker to carry out LFI attacks where the player can read local files from the server (Flag Store 2). This is possible because insecure flags in the `loadXML` function are set. The `config.ini` file contains the xml mode. While the comment next to it states only the `LIBXML_NONET, LIBXML_DTDLOAD, LIBXML_COMPACT, LIBXML_NOBLANKS` flags are set, actually the `LIBXML_NOENT` flag is set as well. `LIBXML_DTDLOAD` and `LIBXML_NOENT` enable the XXE vulnerability.

3. **Twig Template Injection**: The application uses the Twig templating engine to render the 'about me' section on user profiles. Users can inject Twig templates in their 'about me' section, leading to template injection vulnerability. This is possible, because the custom `markdown` filter renders unsanitized 'about me's. This also can be used to gain LFI (Flag Store 2). To prevent code execution a whitelist has been implemented.

4. **SQL Injection (Unintended)**: An unintended SQL injection vulnerability exists in the profile update function, which allows an attacker to control the keys in the `$profileData` associative array. These keys are then directly appended to the SQL query string without any sanitization or escaping, resulting in SQL injection.

## Flag Stores

1. **Flag Store 1**: Each user has a flag in the database which can be retrieved by exploiting the Mass Assignment vulnerability.

2. **Flag Store 2**: Another set of flags are stored as separate files on the server. These can be accessed by exploiting the Twig Template Injection vulnerability in the 'about me' section of a user's profile or leveraging the XXE to obtain LFI.


## Exploits

1. **Mass Assignment**: Exploiting the Mass Assignment Vulnerability, an attacker can become admin of a course they have not created and access the other enrolled user profiles. These profiles contain flags (Flag Store 1) and can now be accessed by the attacker. The course ID with a flag user and the flag users' id can be found in attack info. See the `exploit_mass_assign` function in the `checker.py` for more information.

2. **XML External Entity (XXE) Injection**: This exploit is possible when uploading a course file. The attacker can inject malicious XML content, that includes an external entity pointing to a local file (such as `file:///service/grades/[FLAGNAME]`). When the course details are viewed, the application tries to parse this XML file and ends up disclosing the contents of the specified local file. The flag filename can be found in attack info. See the `exploit_xxe` function in the `checker.py` for more information.

3. **Twig Template Injection**: The attacker uses the Twig template injection vulnerability in the 'About me' section of a user profile. By inserting Twig expressions (like `{% include 'grades/[FLAGNAME]' %}` or `{{ source('grades/tmp.flag') }}`), the attacker can reveal files, exposing flags from the second flagstore. To exploit this, the attacker needs to create a profile, inject the Twig expression into the 'About me' section, and then visit their profile page to see the evaluated expression. The flag filename can be found in attack info. See the `exploit_ssti` function in the `checker.py` for more information.

4. **SQL Injection (Unintended)**: This exploit can be achieved by manipulating the keys in the `$profileData` associative array, during the profile update process. By controlling the keys and injecting malicious SQL syntax, an attacker can perform unintended operations on the database. This could allow access to sensitive data or manipulation of the data structure.

## Fixes
1. **Mass Assignment**: One way to prevent this would be to strictly define the keys allowed for the `$profileData` associative array, and reject or sanitize any keys that are not in this defined list (also fixes **SQL Injection**).
2. **XML External Entity (XXE) Injection**: Players can update the xml mode in the `config.ini` to not contain the `LIBXML_NONET` and `LIBXML_DTDLOAD` flags.
3. **Twig Template Injection**: Players can either rewrite the `markdown` filter to sanitize user input, or remove tags and functions from the whitelist, that enable file disclosure.

See patch files.