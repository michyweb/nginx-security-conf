# nginx-security-conf
the best security conf for nginx

```bash
# @author: @ricardo090489	
# works in nginx/1.13.4 - OpenSSL 1.0.1t 
	
# don't send the nginx version number in error pages and Server header
server_tokens off;
	

server {
	listen 80;
	listen [::]:80;
	server_name example.com;
	return 301 https://$server_name$request_uri;
}


server {
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server;
	
	access_log /path/to/site/dir/logs/access.log;
	error_log /path/to/site/dir/logs/error.log;
	
	root /path/to/site/dir/webroot;
	# index index.php index.html;
	server_name example.com
	
	ssl_certificate /etc/nginx/ssl/star_forgott_com.crt;
	ssl_certificate_key /etc/nginx/ssl/star_forgott_com.key;
	
	# enable session resumption to improve https performance
	# http://vincent.bernat.im/en/blog/2011-ssl-session-reuse-rfc5077.html
	ssl_session_timeout 1d;
	ssl_session_cache shared:SSL:50m;
	ssl_session_tickets off;
	
	# to generate your dhparam.pem file, run in the terminal
	# openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
	# ssl_dhparam /etc/nginx/ssl/dhparam.pem;
	# We don't use DHE with the current cipher suites. 
	
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
	ssl_prefer_server_ciphers on;
	ssl_ecdh_curve secp384r1;
	
	resolver 8.8.8.8;
	
	# OCSP Stapling ---
	# fetch OCSP records from URL in ssl_certificate and cache them
	ssl_stapling on;
	ssl_stapling_verify on;
	## verify chain of trust of OCSP response using Root CA and Intermediate certs
	ssl_trusted_certificate /path/to/root_CA_cert_plus_intermediates;
	
	# SECURITY HEADERS #
	
	# HSTS
	# Recommended: If the site owner would like their domain to be included in the HSTS preload list https://hstspreload.org/ maintained by Chrome (and used by Firefox and Safari), then use the header below. 
	# Sending the preload directive from your site can have PERMANENT CONSEQUENCES and prevent users from accessing your site and any of its subdomains if you find you need to switch 
	# back to HTTP. Please read the details at hstspreload.appspot.com/#removal before sending the header with "preload".
	# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
	# The `preload` flag indicates the site owner's consent to have their domain preloaded. The site owner still needs to then go and submit the domain to the list.
	add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
	
	# Httpoxy vulnerability
	proxy_set_header Proxy "";
	
	# Prevent Information leaks
	proxy_hide_header X-Powered-By;
	proxy_hide_header Server;
	proxy_hide_header X-AspNetMvc-Version;
	proxy_hide_header X-AspNet-Version;
	
	# http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html
	proxy_set_header clientIPAddress "";
	proxy_set_header x-forwarded-for "";
	proxy_set_header client-ip "";
	proxy_set_header forwarded "";
	proxy_set_header from  "";
	proxy_set_header referer "";
	proxy_set_header x-client-ip "";
	proxy_set_header x-originating-ip "";
	proxy_set_header x-wap-profile "";
	
	# http security headers
	add_header X-Content-Type-Options nosniff;
	add_header X-Frame-Options DENY;
	add_header Pragma no-cache;
	add_header Cache-Control no-store;
	add_header X-XSS-Protection "1; mode=block";
	add_header Referrer-Policy origin-when-cross-origin;
	add_header X-Permitted-Cross-Domain-Policies none;
	
	# Add Security cookie flags 
	proxy_cookie_path ~(.*) "$1; SameSite=strict; secure; httponly";
	
	# nonce!!, upgrade-insecure-requests!!
	add_header Content-Security-Policy "upgrade-insecure-requests; default-src 'self'; base-uri 'self'; require-sri-for script; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' 'nonce-JjECqn6A' http: https:; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; media-src 'none'; frame-src 'self'; font-src 'self'; connect-src 'self' wss:; report-uri https://yourdomain.report-uri.com/r/d/csp/enforce;"
	
	# Deprecated
	# add_header Public-Key-Pins 'pin-sha256="XXXXXXXXXXXXXX"; pin-sha256="YYYYYYYYYYYYYYYYYY";'; max-age=10000; includeSubDomains;
	
	
	location / {
		try_files $uri $uri/ /index.php;
	}

	location ~ \.php$ {
		proxy_set_header X-Real-IP  $remote_addr;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header Host $host;
		proxy_pass http://127.0.0.1:8080;
	}
	
	
	# MANAGE ERRORS AND AVOID SERVE CERTAIN FILES # 
	
	add_header Allow "GET, POST, HEAD";
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

Thanks to:

1. https://mozilla.github.io/server-side-tls/ssl-config-generator/
2. https://scotthelme.co.uk/
3. https://report-uri.io/home/tools
4. https://securityheaders.io/
