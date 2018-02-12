require'base64'
require'openssl'
require'uri'
require'json'
require'net/http'

module T4R
	class OAuth

		attr_accessor :consumer_key,:consumer_key_secret,:access_token,:access_token_secret,:user_id,:screen_name,:userAgent
		def initialize(ck ,cks ,at = nil ,ats = nil)
			@consumer_key = ck
			@consumer_key_secret = cks
			@access_token = at
			@access_token_secret = ats
			@userAgent = 'cocoa'
		end
		def request_token(callback)

			oauth_params = oauth
			oauth_params.delete('oauth_token')
			oauth_params['oauth_callback'] = callback
			base_params = Hash[oauth_params.sort]
			query = build_query(base_params)
			url = 'https://api.twitter.com/oauth/request_token'
			base = 'POST&' + escape(url) + '&' + escape(query)
			key = @consumer_key_secret + '&'
			oauth_params['oauth_signature'] = Base64.encode64(OpenSSL::HMAC.digest("sha1",key, base)).chomp
			header = {'Authorization' => 'OAuth ' + build_header(oauth_params),'User-Agent' => @userAgent}
			response = post_request(url,'',header)
			begin
				items = response.body.split('&')
				@request_token = items[0].split('=')[1]
				@request_token_secret = items[1].split('=')[1]
				return [@request_token,@request_token_secret]
			rescue
				raise T4RException,response.body
			end

		end

		def access_token(verifier)

			oauth_params = oauth
			oauth_params.delete('oauth_token')
			oauth_params['oauth_verifier'] = verifier
			oauth_params['oauth_token'] = @request_token
			base_params = Hash[oauth_params.sort]
			query = build_query(base_params)
			url = 'https://api.twitter.com/oauth/access_token'
			base = 'POST&' + escape(url) + '&' + escape(query)
			key = @consumer_key_secret + '&' + @request_token_secret
			oauth_params['oauth_signature'] = Base64.encode64(OpenSSL::HMAC.digest("sha1",key, base)).chomp
			header = {'Authorization' => 'OAuth ' + build_header(oauth_params),'User-Agent' => @userAgent}
			body = ''
			response = post_request(url,body,header)
			begin
				access_tokens = response.body.split('&')
				@access_token = access_tokens[0].split('=')[1]
				@access_token_secret = access_tokens[1].split('=')[1]
				@user_id = access_tokens[2].split('=')[1]
				@screen_name = access_tokens[3].split('=')[1]

				return [@access_token,@access_token_secret,@user_id,@screen_name]
			rescue
				raise T4RException,response.body
			end
		end


		def post(endpoint,additional_params = Hash.new)

			url = url(endpoint)
			header = signature('POST',url,additional_params)
			body = build_body(additional_params)
			response = post_request(url,body,header)
			return decode(response)

		end


		def get(endpoint,additional_params = Hash.new)

			url = url(endpoint)
			header = signature('GET',url,additional_params)
			body = build_body(additional_params)
			response = get_request(url,body,header)
			return decode(response)

		end

		def open
			handle = Net::HTTP.new("api.twitter.com",443)
			handle.use_ssl = true
			handle.verify_mode = OpenSSL::SSL::VERIFY_NONE
			handle.start { |h|
				yield h
			}
		end

		def post_beta(h,endpoint,additional_params = Hash.new)

			url = url(endpoint)
			uri = URI.parse(url)
			header = signature('POST',url,additional_params)
			body = build_body(additional_params)
			response = h.post(uri.request_uri,body,header)
			return decode(response)

		end


		def get_beta(h,endpoint,additional_params = Hash.new)

			url = url(endpoint)
			uri = URI.parse(url)
			header = signature('GET',url,additional_params)
			body = build_body(additional_params)
			response = h.get(uri.request_uri + '?' + body,header)
			return decode(response)

		end


		def streaming(endpoint,additional_params = Hash.new)

			url = url(endpoint)
			header = signature('POST',url,additional_params)
			body = build_body(additional_params)
			buffer = ''
			streaming_request(url,body,header){|chunk|
				if buffer != ''
					chunk = buffer + chunk
					buffer = ''
				end
				begin
					status = JSON.parse(chunk)
				rescue
					buffer << chunk
					next
				end

				yield status
			}

		end

		def login(screen_name,password)
			# 認証URL取得
			res = self.request_token("")

			url = "https://api.twitter.com/oauth/authorize?oauth_token=#{res[0]}"

			# cookie 取得
			uri = URI.parse(url)
			handle = Net::HTTP.new(uri.host,uri.port)
			if uri.port == 443
			  handle.use_ssl = true
			  handle.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
			cookie = []
			html = handle.start do |h|
			  res = h.get(uri.request_uri)
			  cookie = res.get_fields('Set-Cookie')
			  res.body
			end

			# cookie作成
			cookie_str = ""
			cookie.each do |c|
			  c_array = c.split(";")
			  cookie_str += c_array[0] + ";"
			end
			cookie_str = cookie_str.chop

			# 正規表現でマッチ
			/<input name="authenticity_token" type="hidden" value="(.+)">/ =~ html
			authenticity_token = $1
			/<input name="redirect_after_login" type="hidden" value="(.+)">/ =~ html
			redirect_after_login = $1
			/<input id="oauth_token" name="oauth_token" type="hidden" value="(.+)">/ =~ html
			oauth_token = $1
			/<form action="(.+)" id="oauth_form" method="post" target="_self">/ =~ html
			url = $1

			# POSTデータ作成
			post_data = {
			  "authenticity_token" => authenticity_token,
			  "redirect_after_login" => redirect_after_login,
			  "oauth_token" => oauth_token,
			  "session[username_or_email]" => screen_name,
			  "session[password]" => password,
			}

			post_body = post_data.map { |key,value|"#{key}=#{value}"}.join("&")

			# POST通信
			uri = URI.parse(url)
			handle = Net::HTTP.new(uri.host,uri.port)
			if uri.port == 443
			  handle.use_ssl = true
			  handle.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
			html = handle.start do |h|
			  res = h.post(uri.request_uri,post_body,{"Cookie"=>cookie_str})
			  res.body
			end
			# 正規表現
			/<kbd aria-labelledby="code-desc"><code>(.+)<\/code><\/kbd>/ =~ html
			pin = $1

			# a,as取得
			self.access_token(pin)

		end

		private
		def signature(method,url,additional_params)
			oauth_params = oauth
			base_params = oauth_params.merge(additional_params)
			base_params = Hash[base_params.sort]
			query = build_query(base_params)
			base = method + '&' + escape(url) + '&' + escape(query)
			key = @consumer_key_secret + '&' +  @access_token_secret
			oauth_params['oauth_signature'] = Base64.encode64(OpenSSL::HMAC.digest("sha1",key, base)).chomp
			header = {'Authorization' => 'OAuth ' + build_header(oauth_params),'User-Agent' => @userAgent,'Accept-Encoding' => 'identity'}
			return header
		end

		def oauth
			{
				'oauth_consumer_key'     => @consumer_key,
				'oauth_signature_method' => 'HMAC-SHA1',
				'oauth_timestamp'        => Time.now.to_i.to_s,
				'oauth_version'          => '1.0',
				'oauth_nonce'            => Random.new_seed.to_s,
				'oauth_token'            => @access_token
			}
		end

		def decode(response)
			if response.body == nil
				raise T4RException,'Failed to receive response.'
			end
			if response.body == ''
				raise T4RException,'Empty response.'
			end
			begin
				obj = JSON.parse(response.body)
			rescue
				return response.body
			end
			if obj.include?('error')
				raise T4RException,obj['error']
			end
			if obj.include?('errors')
				if obj['errors'].kind_of?(String)
					raise T4RException,obj['errors']
				else
					messages = []
					obj['errors'].each{|errors|
						messages << errors['message']
					}
					raise T4RException,messages.join("\n")
				end
			end
			return obj
		end


		def escape(value)

			URI.escape(value.to_s,/[^a-zA-Z0-9\-\.\_\~]/)

		end

		def post_request(url,body,header)

			uri = URI.parse(url)
			https = Net::HTTP.new(uri.host, uri.port)
			if uri.port == 443
				https.use_ssl = true
				https.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
			response = https.start{|https|
				https.post(uri.request_uri,body,header)
			}
			return response

		end

		def get_request(url,body,header)

			uri = URI.parse(url)
			https = Net::HTTP.new(uri.host, uri.port)
			if uri.port == 443
				https.use_ssl = true
				https.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
			response = https.start{|https|
				https.get(uri.request_uri + '?' + body, header)
			}
			return response

		end

		def streaming_request(url,body,header)

			uri = URI.parse(url)
			https = Net::HTTP.new(uri.host, uri.port)
			if uri.port == 443
				https.use_ssl = true
				https.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
			req = Net::HTTP::Post.new(uri.request_uri + '?' + body,header)
			https.request(req){|response|
				response.read_body{|chunk|
					yield chunk
				}
			}
		end

		def url(endpoint)
			if /^https:/ =~ endpoint
				return endpoint
			end
			list = {
				'media/upload'    => 'https://upload.twitter.com/1.1/media/upload.json',
				'statuses/filter' => 'https://stream.twitter.com/1.1/statuses/filter.json',
				'statuses/sample' => 'https://stream.twitter.com/1.1/statuses/sample.json',
				'user'            => 'https://userstream.twitter.com/1.1/user.json',
				'site'            => 'https://sitestream.twitter.com/1.1/site.json'
			}
			if list.include?(endpoint)
				return list[endpoint]
			else
				return "https://api.twitter.com/1.1/#{endpoint}.json"
			end

		end

		def build_query(params)

			query = params.map{|key,value|
				"#{escape(key)}=#{escape(value)}"
			}.join('&')
			return query

		end

		def build_header(params)

			header = params.map{|key,value|
				"#{escape(key)}=\"#{escape(value)}\""
			}.join(',')
			return header

		end

		def build_body(params)

			body = params.map{|key,value|
				"#{escape(key)}=#{escape(value)}"
			}.join('&')
			return body

		end

		class T4RException < RuntimeError; end
	end

end
