# This Configuration Assumes Nginx as a Reverse Proxy and Certbot SSL Certs

To automate generating most of this, use nginxconfig.io so the configurations to `include` are within that directory. 

```
#/etc/nginx/sites-available/fae2.example.com.conf

upstream apache {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name fae2.example.com;
    root /opt/fae2/public_html;

    #ssl on;
    ssl_certificate /etc/letsencrypt/live/fae2.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/fae2.example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/fae2.example.com/chain.pem;

    # security
    include nginxconfig.io/fae2_security.conf;

    # logging
    access_log /var/log/nginx/fae2.example.com.access.log main;
    error_log /var/log/nginx/fae2.example.com.error.log info;

    location /static/ {
        root /opt/fae2/public_html;
        expires 1M;
        #autoindex on;
        add_header Cache-Control "public";
        proxy_ignore_headers "Set-Cookie";
    }

    include nginxconfig.io/fae2_aliases.conf;

    location @proxy_to_apache {
        proxy_pass   http://apache;
        include nginxconfig.io/fae2_reverse_proxy.conf;
    }

    location / {
        try_files $uri @proxy_to_apache;
    }

    # additional config
    include nginxconfig.io/general.conf;

}

server {
    listen 80;
    listen [::]:80;

    server_name fae2.example.com;

    include nginxconfig.io/letsencrypt.conf;

    location / {
        return 301 https://fae2.example.com$request_uri;
    }
}
```

Not sure about how the reverse proxy would handle HTTP2 due to the headers in `fae2_reverse_proxy.conf` set so have omitted it.

Also not sure whether or not code block for the HTTPS server should include `default_server` (but suspect it probably should) such as:

```
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
```

## Security Settings
These are adapted from the generated settings. There's a good chence these settings will need customized for you preferences and settings.

This is a very permissive (i.e. possibly insecure) Referrer-Policy because I was sites that are audited to be more likely to know they have been audited (assuming someone clicks a link in the report, I want it to tell sites, even HTTP only sites, where that traffic came from).

The HSTS headers are commented out and will not be uncommented until everything is throughly tested and verified. 

```
# /etc/nginx/nginxconfig.io/fae2_security.conf

# security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "unsafe-url" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
#add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# . files
location ~ /\.(?!well-known) {
    deny all;
}

```

## Aliases
These aren't aliases anymore, the Nginx docs say it's better to use the `root` for my set up but you'll get the idea, adjust to your set up:
```
# /etc/nginx/nginxconfig.io/fae2_aliases.conf

    location = /robots.txt {
        root /opt/fae2/public_html/static;
        log_not_found off;
        access_log off;
    }
    location = /sitemap.xml {
        root /opt/fae2/public_html/static;
        log_not_found off;
        access_log off;
    }
    location = /favicon.ico {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /browserconfig.xml {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon-120x120.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon-60x60.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon-180x180.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /favicon-32x32.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon-76x76.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /safari-pinned-tab.svg {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /apple-touch-icon-152x152.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /android-chrome-512x512.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /site.webmanifest {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /android-chrome-192x192.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /mstile-310x310.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /mstile-150x150.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
    location = /favicon-16x16.png {
        root /opt/fae2/public_html/static/favicons;
        log_not_found off;
        access_log off;
    }
```

## Nginx Reverse Proxy Configuration
```
#/etc/nginx/nginxconfig.io/fae2_reverse_proxy.conf

#proxy_pass_request_headers off;
proxy_http_version  1.1;
proxy_cache_bypass  $http_upgrade;

proxy_set_header Upgrade            $http_upgrade;
proxy_set_header Connection         "upgrade";
proxy_set_header Host               $host;
proxy_set_header X-Client-IP        $remote_addr;
proxy_set_header X-Real-IP          $remote_addr;
proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto  $scheme;
proxy_set_header X-Forwarded-Host   $host;
proxy_set_header X-Forwarded-Port   $server_port;
```

This expands upon the `proxy_params` that ship with Nginx. The `X-Client-IP` and `X-Real-IP` directives are redundant but most Nginx xonfigs use one and most Apache Configs use the other (not sure which is which) so just to cover alll the bases.

## General
```
#/etc/nginx/nginxconfig.io/general.conf

# favicon.ico
#location = /favicon.ico {
#   log_not_found off;
#   access_log off;
#}
#
## robots.txt
#location = /robots.txt {
#   log_not_found off;
#   access_log off;
#}

# assets
location ~* \.(?:css(\.map)?|js(\.map)?)$ {
    expires 30d;
    access_log on;
}

# media
location ~* \.(?:jpe?g|png|gif|cur|heic|webp|tiff?|mp3|m4a|aac|ogg|midi?|wav|mp4|mov|webm|mpe?g|avi|ogv|flv|wmv)$ {
    expires 30d;
    access_log on;
}

location ~* \.ico$ {
    expires 90d;
    access_log off;
}
# svg
location ~* \.svgz?$ {
    add_header Access-Control-Allow-Origin "*";
    expires 30d;
    access_log off;
}

# fonts
location ~* \.(?:ttf|ttc|otf|eot|woff2?)$ {
    add_header Access-Control-Allow-Origin "*";
    expires 30d;
    access_log off;
}

# gzip
#gzip on;
#gzip_vary on;
#gzip_proxied any;
#gzip_comp_level 6;
#gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

```

The `favicon.ico` and `robots.txt` directives are comment out due to duplicate locations in `fae2_aliases.conf`.

Double check the Gzip settings, for an HTTPS server, I'm pretty sure they should not be enabled for security reasons.

## Let's Encrypt configuration

```
#/etc/nginx

# ACME-challenge
location ^~ /.well-known/acme-challenge/ {
    root /var/www/_letsencrypt;
}
```

Surprisingly, this goes in the `server` block for port 80.

I guess that's why to use Certbot you already need to have your website/appalication online on port 80 (i.e. HTTP).

## The Main Nginx Configuration File
Just to be through, the main configuration file, `/etc/nginx/nginx.conf` contains:
```
user  www-data;
worker_processes  auto;
error_log  /var/log/nginx/error.log debug;
pid        /var/run/nginx.pid;

events {
    multi_accept on;
    worker_connections  1024;
}

http {
    include /etc/nginx/mime.types;
    default_type  application/octet-stream;

    charset utf-8;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    log_subrequest on;
    keepalive_timeout 99;
    types_hash_max_size 2048;
    client_max_body_size 16M;
    server_names_hash_bucket_size 64;
    server_name_in_redirect off;

    log_format vhost
    '$remote_addr - $remote_user [$time_local] $host:$server_port '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log vhost;

    # SSL
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # Diffie-Hellman parameter for DHE ciphersuites
    ssl_dhparam /etc/nginx/dhparam.pem;

    # Mozilla Intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 208.67.222.222 208.67.220.220 8.8.8.8 8.8.4.4 valid=60s;
    resolver_timeout 2s;

    #gzip  on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

```


## Additional Settings needed in `base.py`

```
#https://docs.djangoproject.com/en/2.2/topics/security/

SECURE_SSL_REDIRECT = True

# This HTTP Header informs Django HTTPS is enabled on the reverse proxy
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

USE_X_FORWARDED_HOST = True

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Strict'

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Strict'

```

Make sure to change the `SITE_URL` to be prefixed by https:// in `secrets.json`

## Apache 2.4x Vhost Configuration

**WARNING:** Using this configuration, my 2vCPU and 4GB of memory cloud-based VM started running out of memory when I was first deploying it into production; I plan to try using few processes (maybe 3 instead of 4 to start), fewer threads, less verbose logging (I was using `debug`, then `trace1`, then `trace8` trying to diagnose problems with HTTPS) and getting rid of unneeded software running on my server for security reasons and to lighten the load on it and if that doesn't work upgrading (no need to pay more while getting things set up).

For the sake of completeness, here's the Apache configuration I'm using:
```
#/etc/apache2/sites-available/fae2.example.com.conf

<VirtualHost *:8080>

  ServerName 127.0.0.1
  DocumentRoot /opt/fae2/public_html

  <Directory /opt/fae2/public_html>
    <IfVersion < 2.4>
      Order allow,deny
      Allow from all
    </IfVersion>
    <IfVersion >= 2.4>
      Require all granted
    </IfVersion>
  </Directory>

  WSGIDaemonProcess fae2 processes=4 python-home=/opt/fae2/venv python-path=/opt/fae2:/opt/fae2/fae2/fae2 lang='en_US.UTF-8' locale='en_US.UTF-8' queue-timeout=45 socket-timeout=60 connect-timeout=15 request-timeout=600 startup-timeout=15 deadlock-timeout=60 graceful-timeout=15 restart-interval=86400 shutdown-timeout=50 maximum-requests=10000 display-name=%{GROUP}

  WSGIScriptAlias / /opt/fae2/fae2/fae2/wsgi.py process-group=fae2

  WSGIProcessGroup  fae2
  WSGIApplicationGroup %{GLOBAL}

  <Directory /opt/fae2/fae2/fae2>
    <IfVersion < 2.4>
      <Files wsgi.py>
        Order allow,deny
        Allow from all
      </Files>
    </IfVersion>
    <IfVersion >= 2.4>
      <Files wsgi.py>
        Require all granted
      </Files>
    </IfVersion>
   </Directory>

  RemoteIPHeader X-Client-IP
  RemoteIPInternalProxy 127.0.0.1

  # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
  # error, crit, alert, emerg.
  LogLevel info

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

   # For most configuration files from conf-available/, which are
   # enabled or disabled at a global level, it is possible to
   # include a line for only one particular virtual host. For example the
   # following line enables the CGI configuration for this host only
   # after it has been globally disabled with "a2disconf".
   #Include conf-available/serve-cgi-bin.conf

</VirtualHost>
```

```
#/etc/apache2/ports.conf

# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 8080

#<IfModule ssl_module>
#   Listen 4430
#</IfModule>

#<IfModule mod_gnutls.c>
#   Listen 4430
#</IfModule>

```

```
#/etc/apache2/apache.conf

#
# !!!!!!!!!!!!!
# APACHE IS HERE JUST FOR MOD_WSGI
# Everything else is served by Nginx
# which acts as a reverse proxy to Apache
# It might seem like overkill but that's how badly
# uWSGI and Gunicorn suck with regards to Django
#
# Nginx listens on :80 & :443, Apache listens on :8080
#

# This is the main Apache server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See http://httpd.apache.org/docs/2.4/ for detailed information about
# the directives and /usr/share/doc/apache2/README.Debian about Debian specific
# hints.
#
#
# Summary of how the Apache 2 configuration works in Debian:
# The Apache 2 web server configuration in Debian is quite different to
# upstream's suggested way to configure the web server. This is because Debian's
# default Apache2 installation attempts to make adding and removing modules,
# virtual hosts, and extra configuration directives as flexible as possible, in
# order to make automating the changes and administering the server as easy as
# possible.

# It is split into several files forming the configuration hierarchy outlined
# below, all located in the /etc/apache2/ directory:
#
#   /etc/apache2/
#   |-- apache2.conf
#   |   `--  ports.conf
#   |-- mods-enabled
#   |   |-- *.load
#   |   `-- *.conf
#   |-- conf-enabled
#   |   `-- *.conf
#   `-- sites-enabled
#       `-- *.conf
#
#
# * apache2.conf is the main configuration file (this file). It puts the pieces
#   together by including all remaining configuration files when starting up the
#   web server.
#
# * ports.conf is always included from the main configuration file. It is
#   supposed to determine listening ports for incoming connections which can be
#   customized anytime.
#
# * Configuration files in the mods-enabled/, conf-enabled/ and sites-enabled/
#   directories contain particular configuration snippets which manage modules,
#   global configuration fragments, or virtual host configurations,
#   respectively.
#
#   They are activated by symlinking available configuration files from their
#   respective *-available/ counterparts. These should be managed by using our
#   helpers a2enmod/a2dismod, a2ensite/a2dissite and a2enconf/a2disconf. See
#   their respective man pages for detailed information.
#
# * The binary is called apache2. Due to the use of environment variables, in
#   the default configuration, apache2 needs to be started/stopped with
#   /etc/init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
#   work with the default configuration.


# Global configuration
#

#
# ServerRoot: The top of the directory tree under which the server's
# configuration, error, and log files are kept.
#
# NOTE!  If you intend to place this on an NFS (or otherwise network)
# mounted filesystem then please read the Mutex documentation (available
# at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
# you will save yourself a lot of trouble.
#
# Do NOT add a slash at the end of the directory path.
#
#ServerRoot "/etc/apache2"

# Server name shouldn't conflict with Nginx so commented out
#ServerName fae2.example.com

#
# The accept serialization lock file MUST BE STORED ON A LOCAL DISK.
#
#Mutex file:${APACHE_LOCK_DIR} default

#
# The directory where shm and other runtime files will be stored.
#

DefaultRuntimeDir ${APACHE_RUN_DIR}

#
# PidFile: The file in which the server should record its process
# identification number when it starts.
# This needs to be set in /etc/apache2/envvars
#
PidFile ${APACHE_PID_FILE}

#
# Timeout: The number of seconds before receives and sends time out.
#
Timeout 300

#
# KeepAlive: Whether or not to allow persistent connections (more than
# one request per connection). Set to "Off" to deactivate.
#
KeepAlive On

#
# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. Set to 0 to allow an unlimited amount.
# We recommend you leave this number high, for maximum performance.
#
MaxKeepAliveRequests 100

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection.
#
KeepAliveTimeout 60


# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}

#
# HostnameLookups: Log the names of clients or just their IP addresses
# e.g., www.apache.org (on) or 204.62.129.132 (off).
# The default is off because it'd be overall better for the net if people
# had to knowingly turn this feature on, since enabling it means that
# each client request will result in AT LEAST one lookup request to the
# nameserver.
#
HostnameLookups Off

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog ${APACHE_LOG_DIR}/error.log

#
# LogLevel: Control the severity of messages logged to the error_log.
# Available values: trace8, ..., trace1, debug, info, notice, warn,
# error, crit, alert, emerg.
# It is also possible to configure the log level for particular modules, e.g.
# "LogLevel info ssl:warn"
#
LogLevel debug

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf


# Sets the default security model of the Apache2 HTTPD server. It does
# not allow access to the root filesystem outside of /usr/share and /var/www.
# The former is used by web applications packaged in Debian,
# the latter may be used for local directories served by the web server. If
# your system is serving content from a sub-directory in /srv you must allow
# access here, or in any related virtual host.
<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<Directory /usr/share>
    AllowOverride None
    Require all granted
</Directory>

<Directory /var/www>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

#<Directory /srv/>
#   Options Indexes FollowSymLinks
#   AllowOverride None
#   Require all granted
#</Directory>

# Handled at vhost level
#<Directory /opt/fae2/public_html>
#    AllowOverride None
#    Require all granted
#</Directory>


# AccessFileName: The name of the file to look for in each directory
# for additional configuration directives.  See also the AllowOverride
# directive.
#
# Using `AllowOverride` and forcing Apache to look for .htaccess
# files and therefore configurations is bad for performance, avoid if possible.
#
AccessFileName .htaccess


#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>


#
# The following directives define some format nicknames for use with
# a CustomLog directive.
#
# These deviate from the Common Log Format definitions in that they use %O
# (the actual bytes sent including headers) instead of %b (the size of the
# requested file), because the latter makes it impossible to detect partial
# requests.
#
# Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
# Use mod_remoteip instead.
#
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined

## The line below (and the modified copy of it below that)
## are a modification suggested in an article I read but about
## configuring `mod_remoteip` but I forget what it does.

#LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include of directories ignores editors' and dpkg's backup files,
# see README.Debian for details.

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf

# Security Settings #
ServerSignature off
ServerTokens Prod

```


---------------------

I'm not fully satisfied with this configuration, because so far, using a reverse proxy is seeming to be more work that it's worth so far but it's better than the very, very few examples of using Nginx (1.19.x) as a reverse proxy in front of Apache (2.4.x) with `mod_wsgi` and Django (2.2.x) that I could find when I searched.

Pull requests welcome.
