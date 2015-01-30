-- Monarch API authentication for Nginx and Lua
-- Copyright (C) 2015 Phil Kedy
-- License MIT

local M = {
	_VERSION = '0.1',
	_HEADER_VERSION = 1
}

local resty_sha256 = require "resty.sha256"
local resty_hmac = require "resty.hmac"
local url = require "net.url"
local cjson = require "cjson"

local function random_alphanumeric(length)
	local random = "";

	for i = 1, length do
		local n = math.random(55, 116);

		if n < 65 then
			n = n - 7;
		elseif n > 90 then
			n = n + 6;
		end

		random = random .. string.char(n);
	end

	return random;
end

local function get_port(host_header, scheme)
	local port = host_header:match(":(%d+)$");

	if port == nil then
		if scheme == "http" then
			port = 80;
		elseif scheme == "https" then
			port = 443;
		end
	else
		port = tonumber(port);
	end

	return port;
end

local function get_mime_type(content_type)
	local mimeType = ""

	if (content_type ~= nil) then
		mimeType = content_type;

		local semi = string.find(mimeType, ";")

		if semi ~= nil then
			mimeType = string.gsub(mimeType.sub(1, semi - 1), "%s$", "");
		end
	end

	return mimeType;
end

local function empty_string_if_null(value)
	if (value ~= nil) then
		return value;
	else
		return "";
	end
end

local function new_line_delimited(table_value)
	return table.concat(table_value, "\n") .. "\n";
end

local function calc_sha256_base64_encoded(data)
	local sha256 = resty_sha256:new();
	sha256:update(data);
	local digest = sha256:final();

	return ngx.encode_base64(digest);
end

local function calc_hmac_base64_encoded(data, secret)
	local hmac = resty_hmac:new()
	local digest = hmac:digest("sha256", secret, data, true)

	return ngx.encode_base64(digest);
end

local function add_cors()
	if ngx.var.http_origin ~= nil then
		ngx.header["Access-Control-Allow-Origin"] = ngx.var.http_origin;
		ngx.header["Access-Control-Allow-Methods"] = "GET, POST, HEAD, OPTIONS, DELETE, PUT, PATCH";
		ngx.header["Access-Control-Allow-Headers"] = "Content-Type, Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Api-Key, X-Api-Key, Authorization";
		ngx.header["Access-Control-Allow-Credentials"] = "true";
		ngx.header["Access-Control-Max-Age"] = "1728000";
	end
end

local function calc_payload_hash(mime_type, content)
	local payload = new_line_delimited({
		"hawk.1.payload",
		mime_type,
		content
	});

	return calc_sha256_base64_encoded(payload);
end

-------------

M.authenticate = function()
	local method = ngx.req.get_method();
	local scheme = ngx.var.scheme;
	local host = ngx.var.host;
	local port = get_port(ngx.var.http_host, scheme);
	local uri = ngx.var.request_uri;
	local path = ngx.var.uri;
	local querystring = ngx.var.query_string;
	local headers = ngx.req.get_headers();
	local headersArys = {};
	local mimeType = get_mime_type(ngx.var.content_type);
	local content = empty_string_if_null(ngx.var.request_body);

	local bytes_received = string.len(method) + string.len(uri) + string.len(content) + 11;

	for k, v in pairs(headers) do
		headersArys[k] = {v};
		bytes_received = bytes_received + string.len(k) + string.len(v) + 2;
	end

	local payload_hashes = {};

	payload_hashes["Hawk V1"] = {
		sha256 = calc_payload_hash(mimeType, content)
	};

	local authenticate_request = cjson.encode({
		method = method,
		protocol = scheme,
		host = host,
		port = port,
		path = path,
		querystring = querystring,
		headers = headersArys,
		ipAddress = ngx.var.remote_addr,
		payloadHashes = payload_hashes,
		requestWeight = 1.0,
		performAuthorization = true
	});

	local ts = os.time();
	local nonce = random_alphanumeric(6);

	local payload_hash = calc_payload_hash("application/json", authenticate_request);

	local header = new_line_delimited({
		'hawk.1.header',
		tostring(ts),
		nonce,
		"POST",
		"/service/v1/requests/authenticate",
		"localhost",
		tostring(8000),
		payload_hash,
		""
	});

	local header_hash = calc_hmac_base64_encoded(header, ngx.var.shared_secret);
	local authorization = 'Hawk id="' .. ngx.var.provider_key .. '", ts="' .. ts .. '", nonce="' .. nonce .. '", hash="' .. payload_hash .. '"' .. ', mac="' .. header_hash .. '"';

	local res = ngx.location.capture("/monarch_auth", {
		method = ngx.HTTP_POST,
		body = authenticate_request,
		vars = {
			authorization = authorization
		}
	});

	ngx.var.bytes_received = bytes_received;
	ngx.var.real_path = path;
	ngx.var.real_args = ngx.var.args;

	if res.status ~= 200 then
		ngx.status = 503;

		add_cors();

		ngx.header.content_type = "application/json";
		ngx.print("{\"code\":503,\"reason\":\"systemUnavailable\",\"message\":\"The system is currently unavailable\",\"developerMessage\":\"Please try again later.\",\"errorCode\":\"SYS-0001\" }");
		return;
	else
		local authResp = cjson.decode(res.body);
		ngx.log(ngx.INFO, res.body);
		local vars = authResp.vars;

		ngx.var.provider_id = vars.providerId;
		ngx.var.service_id = vars.serviceId;
		ngx.var.service_version = vars.serviceVersion;
		ngx.var.operation_name = vars.operation;
		ngx.var.token_id = nil;
		ngx.var.user_id = nil;

		if authResp.code ~= 200 then
			ngx.var.reason = authResp.reason;
			ngx.status = authResp.code;

			add_cors();

			ngx.log(ngx.ERR, "Authentication failed");
			ngx.header.content_type = res.header["Content-Type"];

			if authResp.responseHeaders ~= nil then
				local headers = authResp.responseHeaders;

				for i, hdr in ipairs(headers) do
					ngx.header[hdr.name] = hdr.value;
				end
			end

			return;
		else
			local apiContext = authResp.context;

			ngx.var.reason = "ok";

            if apiContext ~= nil then
                ngx.var.application_id = (apiContext.application ~= cjson.null and apiContext.application.id or nil)
                ngx.var.client_id = (apiContext.client ~= cjson.null and apiContext.client.id or nil)

                if apiContext.token ~= cjson.null then
                    if type(apiContext.token.id) == "string" then
                        ngx.log(ngx.INFO, apiContext.token.id);
                        ngx.var.token_id = apiContext.token.id;
                    end
                end

                if apiContext.principal ~= cjson.null then
                    if type(apiContext.principal.id) == "string" then
                        ngx.var.user_id = apiContext.principal.id;
                    end
                end
            end
		end
	end

	ngx.log(ngx.INFO, "Authentication succeeded");
end

M.send_traffic = function()
	local method = ngx.req.get_method();
	local scheme = ngx.var.scheme;
	local host = ngx.var.host;
	local port = get_port(ngx.var.http_host, scheme);
	local uri = ngx.var.request_uri;
	local path = ngx.var.real_path;
	local querystring = ngx.var.query_string;
	local headers = ngx.req.get_headers();

	local headersArys = {};
	for k, v in pairs(headers) do
		headersArys[k] = {v};
	end

	local pars = nil;

	if ngx.var.real_args ~= nil then
		pars = url.parseQuery(ngx.var.real_args);
	end

	local response_time = math.ceil((ngx.now() - ngx.req.start_time()) * 1000);

	local event_request = cjson.encode({
		request_id = nil,
		application_id = ngx.var.application_id,
		client_id = ngx.var.client_id,
		service_id = ngx.var.service_id,
		service_version = ngx.var.service_version,
		operation_name = ngx.var.operation_name,
		provider_id = ngx.var.provider_id,
		request_size = tonumber(ngx.var.bytes_received),
		response_size = tonumber(ngx.var.bytes_sent),
		response_time = response_time,
		status_code = tonumber(ngx.var.status),
		error_reason = ngx.var.reason,
		cache_hit = false,
		token_id = ngx.var.token_id,
		user_id = ngx.var.user_id,
		host = host,
		path = path,
		port = port,
		verb = method,
		parameters = pars,
		headers = headers,
		client_ip = ngx.var.remote_addr,
		user_agent = ngx.var.http_user_agent
	});

	ngx.log(ngx.INFO, event_request);

	local ts = os.time();
	local nonce = random_alphanumeric(6);

	local payload_hash = calc_payload_hash("application/json", event_request);

	local header = new_line_delimited({
		'hawk.1.header',
		tostring(ts),
		nonce,
		"POST",
		"/analytics/v1/traffic/events",
		"localhost",
		tostring(8000),
		payload_hash,
		""
	});

	local header_hash = calc_hmac_base64_encoded(header, ngx.var.shared_secret);
	local authorization = 'Hawk id="' .. ngx.var.provider_key .. '", ts="' .. ts .. '", nonce="' .. nonce .. '", hash="' .. payload_hash .. '"' .. ', mac="' .. header_hash .. '"';

	local res = ngx.location.capture("/monarch_traffic", {
		method = ngx.HTTP_POST,
		body = event_request,
		vars = {
			authorization = authorization
		}
	});

	if res.status ~= 204 then
		ngx.log(ngx.ERR, "Failed to log traffic");
	else
		ngx.log(ngx.INFO, "Logged traffic successfully");
	end
end

return M;
