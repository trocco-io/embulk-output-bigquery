require 'aws-sdk-sts'

module Embulk
  module Output
    class Bigquery < OutputPlugin
      # AWS Role Chaining用の認証情報サプライヤー
      # AssumeRoleで一時認証情報を取得し、期限前に自動リフレッシュする
      class AwsRoleCredentialsSupplier
        # Role Chainingの最大セッション時間（AWS制限: 1時間）
        SESSION_DURATION_SECONDS = 3600

        # 期限5分前にリフレッシュ
        REFRESH_THRESHOLD_SECONDS = 300

        def initialize(role_arn:, role_session_name: nil, region: nil)
          @role_arn = role_arn
          @role_session_name = role_session_name || 'embulk-bigquery-session'
          @region = region || 'ap-northeast-1'

          @credentials = nil
          @expiration_time = nil
          @mutex = Mutex.new

          Embulk.logger.info { "embulk-output-bigquery: AwsRoleCredentialsSupplier initialized for role: #{@role_arn}" }
        end

        # AWS認証情報を取得（必要に応じてリフレッシュ）
        # @return [Hash] aws_access_key_id, aws_secret_access_key, aws_session_token
        def get_credentials
          @mutex.synchronize do
            refresh_if_needed
            {
              'aws_access_key_id' => @credentials.access_key_id,
              'aws_secret_access_key' => @credentials.secret_access_key,
              'aws_session_token' => @credentials.session_token
            }
          end
        end

        private

        def refresh_if_needed
          return unless should_refresh?

          Embulk.logger.info { "embulk-output-bigquery: Refreshing AWS credentials via AssumeRole" }
          assume_role
          Embulk.logger.info { "embulk-output-bigquery: AWS credentials refreshed, expires at: #{@expiration_time}" }
        end

        def should_refresh?
          return true if @credentials.nil? || @expiration_time.nil?

          # 期限切れ、または期限5分前ならリフレッシュ
          refresh_threshold = Time.now + REFRESH_THRESHOLD_SECONDS
          refresh_threshold >= @expiration_time
        end

        def assume_role
          # DefaultCredentialsProviderを使用（IRSA, ECS Task Role, 環境変数など）
          sts_client = Aws::STS::Client.new(region: @region)

          Embulk.logger.debug { "embulk-output-bigquery: Calling STS AssumeRole for #{@role_arn}" }

          response = sts_client.assume_role(
            role_arn: @role_arn,
            role_session_name: @role_session_name,
            duration_seconds: SESSION_DURATION_SECONDS
          )

          @credentials = response.credentials
          @expiration_time = response.credentials.expiration

          Embulk.logger.debug { "embulk-output-bigquery: AssumeRole succeeded, session: #{@role_session_name}" }
        rescue Aws::STS::Errors::ServiceError => e
          Embulk.logger.error { "embulk-output-bigquery: AssumeRole failed: #{e.class} - #{e.message}" }
          raise ConfigError.new("AWS AssumeRole failed for #{@role_arn}: #{e.message}")
        end
      end
    end
  end
end
