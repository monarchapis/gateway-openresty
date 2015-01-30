Monarch OpenResty-based API Gateway
===================================

Works in tandem with the API Manager to authenticate and authorize requests before proxying them to the appropriate backend service.

Simply overlay the following files into your [OpenResty](http://openresty.org "OpenResty home page") installation directory (e.g. /usr/local/openresty).

- **lualib/monarch.lua** - The main gateway script that handles calling the Monarch API Manager to verify the incoming request.
- **lualib/resty/hmac.lua** - A contributed script that adds HMAC support.
- **lualib/net/url.lua** - A contributed script that parses URLs.
- **nginx/conf/nginx.conf** - The API gateway Nginx configuration.

Next, you will need to edit nginx.conf to configure the following values:

- **Host** and **Environment ID** - Under `location = /monarch_auth` and `location = /monarch_traffic` you will need to update the `Host` and `X-Environment-Id` headers.  The Monarch environment ID can be accessed in the admin console  by clicking the gear icon next to your user name in the upper right-hand corner. Likewise, the `upstream monarch_backend` needs to have the correct host and port.
- **Provider Key** and **Shared Secret** - You will need to create a new Provider in the admin console (e.g. name = gateway, permissions = Authenticate API requests) and change the `set $provider_key "XXXX";` in nginx.conf to have the correct provider API key and shared secret you created for this provider.

Refer to the `location /` for how to enable the communication with Monarch.  You can find documentation on configuring Nginx [on their wiki](http://wiki.nginx.org/Configuration "Nginx configuration").