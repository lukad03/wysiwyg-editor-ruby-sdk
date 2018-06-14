module FroalaEditorSDK

  # Uploads files to S3/AWS
  class S3

    # Builds a signature based on  the options.
    # Params:
    # +options+:: The configuration params that are needed to compute the signature.
    def self.signature (options = nil)
      Base64.encode64(
          OpenSSL::HMAC.digest(
              OpenSSL::Digest.new('sha1'),
              options[:secretKey], self.policy(options)
          )
      ).gsub("\n", "")
    end

    # Encodes to Base64 the policy data and replaces new lines chars.
    # Params:
    # +options+:: The configuration params that are needed to compute the signature.
    def self.policy (options = nil)
      Base64.encode64(self.policy_data(options).to_json).gsub("\n", "")
    end

    # Sets policy params, bucket that will be used max file size and other params.
    # Params:
    # +options+:: Configuration params that are needed to set the policy
    def self.policy_data (options = nil)
      {
          expiration: 10.hours.from_now.utc.iso8601,
          conditions: [
              ["starts-with", "$key", options[:keyStart]],       # Start key/folder
              ["starts-with", "$x-requested-with", "xhr"],  # Request type
              ["starts-with", "$content-type", ""],         # Content type
              {bucket: options[:bucket]},                   # Bucket name
              {acl: options[:acl]},                         # ACL property
              {success_action_status: "201"},               # Response status 201 'file created'
              {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
              {"x-amz-credential": self.credential(options)},
              {"x-amz-date": self.date_string}
          ]
      }
    end

    # Makes all the request in order and returns AWS hash response
    # Params:
    # +options+:: Configuration params to generate the AWS response.
    def self.data_hash (options = nil)
      options[:region] = 'us-east-1' if options[:region].nil? ||  options[:region] == 's3'

      {
        :bucket => options[:bucket],           # Upload bucket
        :region =>  options[:region] != 'us-east-1' ? "s3-#{options[:region]}" : 's3', # Upload region
        :keyStart => options[:keyStart],       # Start key/folder
        :params => {
          acl: options[:acl],
          policy: self.policy(options),
          "x-amz-algorithm": "AWS4-HMAC-SHA256",
          "x-amz-credential": credential(options),
          "x-amz-date": date_string,
          "x-amz-signature": self.signature(options)       
        }
      }
    end

    private

    def self.credential(options = nil)
      [
        options[:accessKey], date_string, options[:region], 's3/aws4_request'
      ]
    end

    def self.date_string
      @date_string ||= Date.today.strftime("%Y%m%d")
    end
  end
end