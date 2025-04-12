require 'google/apis/bigquery_v2'

module Embulk
  module Output
    class Bigquery < OutputPlugin
      # NOTE:
      # Due to the JRuby version constraint in Embulk v0.9, it’s not possible to upgrade to a version of the google-api-client (0.37.0 or later) that includes support for policy_tags.
      # So the workaround was implemented using a patch-like solution as shown below.
      class BigqueryServiceWithPolicyTag < Google::Apis::BigqueryV2::BigqueryService
        def get_table_with_policy_tags(project_id, dataset_id, table_id, selected_fields: nil, fields: nil, quota_user: nil, user_ip: nil, options: nil, &block)
          command = make_simple_command(:get, 'projects/{projectId}/datasets/{datasetId}/tables/{tableId}', options)
          command.response_representation = TableWithPolicyTag::Representation
          command.response_class = TableWithPolicyTag
          command.params['projectId'] = project_id unless project_id.nil?
          command.params['datasetId'] = dataset_id unless dataset_id.nil?
          command.params['tableId'] = table_id unless table_id.nil?
          command.query['selectedFields'] = selected_fields unless selected_fields.nil?
          command.query['fields'] = fields unless fields.nil?
          command.query['quotaUser'] = quota_user unless quota_user.nil?
          command.query['userIp'] = user_ip unless user_ip.nil?
          execute_or_queue_command(command, &block)
        end

        def patch_table_with_policy_tags(project_id, dataset_id, table_id, table_object = nil, autodetect_schema: nil, fields: nil, quota_user: nil, options: nil, &block)
          command = make_simple_command(:patch, 'projects/{+projectId}/datasets/{+datasetId}/tables/{+tableId}', options)
          command.request_representation = TableWithPolicyTag::Representation
          command.request_object = table_object
          command.response_representation = TableWithPolicyTag::Representation
          command.response_class = TableWithPolicyTag
          command.params['projectId'] = project_id unless project_id.nil?
          command.params['datasetId'] = dataset_id unless dataset_id.nil?
          command.params['tableId'] = table_id unless table_id.nil?
          command.query['autodetect_schema'] = autodetect_schema unless autodetect_schema.nil?
          command.query['fields'] = fields unless fields.nil?
          command.query['quotaUser'] = quota_user unless quota_user.nil?
          execute_or_queue_command(command, &block)
        end
      end

      class TableFieldSchemaWithPolicyTag < Google::Apis::BigqueryV2::TableFieldSchema
        class PolicyTags
          include Google::Apis::Core::JsonObjectSupport
          include Google::Apis::Core::Hashable

          class Representation < Google::Apis::Core::JsonRepresentation
            collection :names, as: 'names'
          end

          attr_accessor :names

          def initialize(**args)
            update!(**args)
          end

          def update!(**args)
            @names = args[:names] if args.key?(:names)
          end
        end

        include Google::Apis::Core::Hashable

        attr_accessor :policy_tags

        def update!(**args)
          super
          @policy_tags = args[:policy_tags] if args.key?(:policy_tags)
        end

        class Representation < Google::Apis::BigqueryV2::TableFieldSchema::Representation
          collection :fields, as: 'fields', class: TableFieldSchemaWithPolicyTag, decorator: TableFieldSchemaWithPolicyTag::Representation
          property :policy_tags, as: 'policyTags', class: TableFieldSchemaWithPolicyTag::PolicyTags, decorator: TableFieldSchemaWithPolicyTag::PolicyTags::Representation
        end
      end

      class TableSchemaWithPolicyTag < Google::Apis::BigqueryV2::TableSchema
        class Representation < Google::Apis::BigqueryV2::TableSchema::Representation
          collection :fields, as: 'fields', class: TableFieldSchemaWithPolicyTag, decorator: TableFieldSchemaWithPolicyTag::Representation
        end
      end

      class TableWithPolicyTag < Google::Apis::BigqueryV2::Table
        class Representation < Google::Apis::BigqueryV2::Table::Representation
          property :schema, as: 'schema', class: TableSchemaWithPolicyTag, decorator: TableSchemaWithPolicyTag::Representation
        end
      end
    end
  end
end
