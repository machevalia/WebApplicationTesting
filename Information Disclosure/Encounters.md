# Encounters

# Information Disclosure in Error Messages
Find the version number
## Observations
- Tossed a single quote at the end of the product ID param in the URL. 

# Information Disclosure in Debug Page
Get the secret key
## Observations
- Comment in home page - /cgi-bin/phpinfo.php
- Secret key in php info

# Source code disclosure via backup files
Get the database password from the backup files. 
## Observations
- Bruteforcing shows /backup
- Backup file contains the database password. 

# Authentication bypass via information disclosure
Find the auth bypass to get into Carlos account. 
## Observations
- Quickhits shows /admin
- Admin isn't accessible without being logged in. 
- TRACE enabled. 
-- Trace shows there is a special header X-Custom-IP-Authorization: 23.244.144.126
- Setting the value to 127.0.0.1 allows access. Using that in repeater I deleted Carlos. 

# Information disclosure in version control history
Get into admin and delete carlos
## Observations
- FFUF finds .git
- Downloaded .git
- ```# Show a human-readable view of the index
git ls-files --stage```

```
machevalia@Nicks-MacBook-Air .git % # Show a human-readable view of the index
git ls-files --stage
zsh: command not found: #
100644 21d23f13ce6c704b81857379a3e247e3436f4b26 0	admin.conf
100644 8944e3b9853691431dc58d5f4978d3940cea4af2 0	admin_panel.php
machevalia@Nicks-MacBook-Air .git % git diff HEAD^ HEAD -- admin.conf      
diff --git a/admin.conf b/admin.conf
index 801f8b2..21d23f1 100644
--- a/admin.conf
+++ b/admin.conf
@@ -1 +1 @@
-ADMIN_PASSWORD=we82dwec8pr5qnm1m0mu
+ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```

