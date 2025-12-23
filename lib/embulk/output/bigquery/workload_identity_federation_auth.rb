require 'net/http'
require 'uri'
require 'openssl'
require 'json'

module Embulk
  module Output
    class Bigquery < OutputPlugin
      class WorkloadIdentityFederationAuth
        TOKEN_LIFETIME_SECONDS = 3600

        def initialize(config, scopes)
          @aws_access_key_id = config['aws_access_key_id']
          @aws_secret_access_key = config['aws_secret_access_key']
          @aws_session_token = config['aws_session_token']
          @aws_region = config['aws_region'] || 'ap-northeast-1'
          @scopes = scopes

          wif_config = JSON.parse(config['config'])
          @audience = wif_config['audience']
          @service_account_impersonation_url = wif_config['service_account_impersonation_url']
          @token_url = wif_config['token_url'] || 'https://sts.googleapis.com/v1/token'
        end

        def authenticate
          WorkloadIdentityFederationCredentials.create_and_fetch_token(self)
        end

        def fetch_access_token_info
          aws_request = create_aws_signed_request
          federated_token = exchange_token_for_google_access_token(aws_request)
          result = impersonate_service_account(federated_token)
          {
            'access_token' => result['accessToken'],
            'expire_time' => Time.parse(result['expireTime'])
          }
        end

        private

        def service_account_email
          parts = @service_account_impersonation_url.split('serviceAccounts/')
          raise ConfigError.new("Invalid service_account_impersonation_url: #{@service_account_impersonation_url}") if parts.length < 2
          parts[1].gsub(':generateAccessToken', '')
        end

        def create_aws_signed_request
          service = 'sts'
          host = "sts.#{@aws_region}.amazonaws.com"
          method = 'POST'

          now = Time.now.utc
          amz_date = now.strftime('%Y%m%dT%H%M%SZ')
          date_stamp = now.strftime('%Y%m%d')

          query_params = 'Action=GetCallerIdentity&Version=2011-06-15'
          endpoint = "https://#{host}/?#{query_params}"

          payload_hash = sha256_hex('')

          headers = {
            'host' => host,
            'x-amz-date' => amz_date,
            'x-goog-cloud-target-resource' => @audience
          }
          headers['x-amz-security-token'] = @aws_session_token if @aws_session_token

          signed_headers_list = headers.keys.sort
          signed_headers = signed_headers_list.join(';')

          canonical_headers = signed_headers_list.map { |k| "#{k}:#{headers[k]}\n" }.join

          query_parts = query_params.split('&').sort
          canonical_querystring = query_parts.join('&')

          canonical_request = [
            method,
            '/',
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
          ].join("\n")

          algorithm = 'AWS4-HMAC-SHA256'
          credential_scope = "#{date_stamp}/#{@aws_region}/#{service}/aws4_request"

          string_to_sign = [
            algorithm,
            amz_date,
            credential_scope,
            sha256_hex(canonical_request)
          ].join("\n")

          signing_key = get_signature_key(date_stamp, @aws_region, service)
          signature = hmac_sha256_hex(signing_key, string_to_sign)

          authorization_header = "#{algorithm} Credential=#{@aws_access_key_id}/#{credential_scope}, SignedHeaders=#{signed_headers}, Signature=#{signature}"

          request_headers = signed_headers_list.map { |key| { 'key' => key, 'value' => headers[key] } }
          request_headers << { 'key' => 'Authorization', 'value' => authorization_header }

          {
            'url' => endpoint,
            'method' => method,
            'headers' => request_headers
          }
        end

        def get_signature_key(date_stamp, region, service)
          k_date = hmac_sha256("AWS4#{@aws_secret_access_key}", date_stamp)
          k_region = hmac_sha256(k_date, region)
          k_service = hmac_sha256(k_region, service)
          hmac_sha256(k_service, 'aws4_request')
        end

        # https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
        def exchange_token_for_google_access_token(aws_request)
          data = URI.encode_www_form({
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'audience' => @audience,
            'scope' => 'https://www.googleapis.com/auth/cloud-platform',
            'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'subject_token_type' => 'urn:ietf:params:aws:token-type:aws4_request',
            'subject_token' => URI.encode_www_form_component(JSON.generate(aws_request))
          })

          uri = URI.parse(@token_url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true

          request = Net::HTTP::Post.new(uri.request_uri)
          request['Content-Type'] = 'application/x-www-form-urlencoded'
          request.body = data

          Embulk.logger.debug { "embulk-output-bigquery: Workload Identity Federation: Exchanging AWS token for Google STS token" }
          Embulk.logger.debug { "embulk-output-bigquery: POST #{@token_url}" }

          response = http.request(request)

          Embulk.logger.debug { "embulk-output-bigquery: Token exchange response code: #{response.code}" }

          unless response.code == '200'
            Embulk.logger.error { "embulk-output-bigquery: Token exchange failed: #{response.code} - #{response.body}" }
            raise "Google STS token exchange failed: #{response.code} - #{response.body}"
          end

          Embulk.logger.info { "embulk-output-bigquery: Token exchange succeeded" }

          response_json = JSON.parse(response.body)
          Embulk.logger.debug {
            safe_response = response_json.select { |k, _| %w[expires_in token_type issued_token_type].include?(k) }
            "embulk-output-bigquery: Token exchange response: #{safe_response.to_json}"
          }
          response_json['access_token']
        end

        # https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
        def impersonate_service_account(federated_token)
          sa_email = service_account_email
          impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/#{sa_email}:generateAccessToken"

          Embulk.logger.debug { "embulk-output-bigquery: Workload Identity Federation: Impersonating service account: #{sa_email}" }
          Embulk.logger.debug { "embulk-output-bigquery: POST #{impersonation_url}" }

          uri = URI.parse(impersonation_url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true

          request_body = {
            'scope' => @scopes,
            'lifetime' => "#{TOKEN_LIFETIME_SECONDS}s"
          }

          request = Net::HTTP::Post.new(uri.request_uri)
          request['Authorization'] = "Bearer #{federated_token}"
          request['Content-Type'] = 'application/json'
          request.body = JSON.generate(request_body)

          response = http.request(request)

          Embulk.logger.debug { "embulk-output-bigquery: Impersonation response code: #{response.code}" }

          unless response.code == '200'
            Embulk.logger.error { "embulk-output-bigquery: Impersonation failed: #{response.code} - #{response.body}" }
            raise "Service account impersonation failed: #{response.code} - #{response.body}"
          end

          Embulk.logger.info { "embulk-output-bigquery: Service account impersonation succeeded" }

          response_json = JSON.parse(response.body)
          Embulk.logger.debug {
            safe_response = response_json.select { |k, _| %w[expireTime].include?(k) }
            "embulk-output-bigquery: Impersonation response: #{safe_response.to_json}"
          }
          {
            'accessToken' => response_json['accessToken'],
            'expireTime' => response_json['expireTime']
          }
        end

        def sha256_hex(data)
          OpenSSL::Digest::SHA256.hexdigest(data)
        end

        def hmac_sha256(key, data)
          OpenSSL::HMAC.digest('SHA256', key, data)
        end

        def hmac_sha256_hex(key, data)
          OpenSSL::HMAC.hexdigest('SHA256', key, data)
        end
      end

      class WorkloadIdentityFederationCredentials < Signet::OAuth2::Client
        def self.create_and_fetch_token(auth)
          credentials = new(auth)
          credentials.refresh_token_info!
          credentials
        end

        def initialize(auth)
          super()
          @auth = auth
        end

        def fetch_access_token!(options = {})
          Embulk.logger.debug { "embulk-output-bigquery: Workload Identity Federation: Refreshing access token" }
          refresh_token_info!
          Embulk.logger.info { "embulk-output-bigquery: Workload Identity Federation: Access token refreshed successfully" }
          { 'access_token' => self.access_token }
        end

        def refresh_token_info!
          token_info = @auth.fetch_access_token_info
          self.access_token = token_info['access_token']
          self.expires_at = token_info['expire_time']
        end
      end
    end
  end
end
