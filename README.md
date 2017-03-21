# nginx-security-conf
the best security conf for nginx

```bash
    
    # nginx 2.2.15 | intermediate profile | OpenSSL 1.0.1e | link
    # Oldest compatible clients: Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1, Windows XP IE8, Android 2.3, Java 7
    
# don't send the nginx version number in error pages and Server header
server_tokens off;
	

server {
    listen 80 default_server;
    listen [::]:80 default_server;

    # Redirect all HTTP requests to HTTPS with a 301 Moved Permanently response.
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    access_log /path/to/site/dir/logs/access.log;
    error_log /path/to/site/dir/logs/error.log;
    
    root /path/to/site/dir/webroot;
    # index index.php index.html;
    server_name XXXXXX.XXXX
    
    ssl_certificate /etc/nginx/ssl/star_forgott_com.crt;
    ssl_certificate_key /etc/nginx/ssl/star_forgott_com.key;
    
    # enable session resumption to improve https performance
    # http://vincent.bernat.im/en/blog/2011-ssl-session-reuse-rfc5077.html
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # to generate your dhparam.pem file, run in the terminal
    # openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
    ssl_prefer_server_ciphers on;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    
    ssl_ciphers " En base a la versión del OpenSSL (que versión tiene?) "
    
    resolver 8.8.8.8;
    
    # OCSP Stapling ---
    # fetch OCSP records from URL in ssl_certificate and cache them
    ssl_stapling on;
    ssl_stapling_verify on;
    ## verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /path/to/root_CA_cert_plus_intermediates;
    
    # SECURITY HEADERS #
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
    
    # Httpoxy vulnerability
    proxy_set_header Proxy "";
    
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Pragma no-cache
    add_header Cache-Control no-store
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy origin-when-cross-origin;
    proxy_cookie_path ~(.*) "$1; SameSite=strict";
    
    # nonce!!, upgrade-insecure-requests!!
    add_header Content-Security-Policy "upgrade-insecure-requests; default-src 'self'; script-src 'self' 'nonce-6B201A99C0EEA8C8' 'unsafe-eval'; object-src 'none'; style-src 'self' data: 'unsafe-inline';img-src 'self' data: assets.zendesk.com; media-src 'none'; frame-src 'self'; font-src 'self'; connect-src 'self'"
    
    add_header Public-Key-Pins 'pin-sha256="XrW0TkAtvDG7BrP+ptnF1MhRuUfu3AL7F5b97pMrunU="; pin-sha256="YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=";' always;
    
    # MANAGE ERRORS AND AVOID SERVE CERTAIN FILES # 
    
    add_header Allow "GET, POST, HEAD" always;
    ## Only allow these request methods ##
    ## Do not accept DELETE, SEARCH and other methods ##
    if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    	return 444;
    }
    
    # Allow access to the ACME Challenge for Let's Encrypt <- <3
    location ~ /\.well-known\/acme-challenge {
    	allow all;
    }
    
    # Deny all attempts to access hidden files
    # such as .htaccess, .htpasswd, .DS_Store (Mac), .git, .etc...
    location ~ /\. {
    	deny all;
    }
    
    error_page 400 401 402 403 404 405 406 407 408 409 410 411 412 413 414 415 416 417 418 420 422 423 424 426 428 429 431 444 449 450 451 500 501 502 503 504 505 506 507 508 509 510 511 /error.html;
    location  /error.html {
    	internal;
    }
	
}

```
