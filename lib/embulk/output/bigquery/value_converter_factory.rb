require 'time'
require 'time_with_zone'
require 'json'
require 'bigdecimal'
require_relative 'helper'

module Embulk
  module Output
    class Bigquery < OutputPlugin
      class ValueConverterFactory
        class NotSupportedType < StandardError; end
        class TypeCastError < StandardError; end

        # ref. https://cloud.google.com/bigquery/preparing-data-for-bigquery

        DEFAULT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%6N" # BigQuery timestamp format
        DEFAULT_TIMEZONE         = "UTC"
        DEFAULT_SCALE            = 9

        # @param [Hash] task
        # @option task [String] default_timestamp_format
        # @option task [String] default_timezone
        # @option task [Hash]   column_options user defined column types
        # @param [Schema] schema embulk defined column types
        # @return [Array] an arary whose key is column_index, and value is its converter (Proc)
        def self.create_converters(task, schema)
          column_options_map       = Helper.column_options_map(task['column_options'])
          default_timestamp_format = task['default_timestamp_format'] || DEFAULT_TIMESTAMP_FORMAT
          default_timezone         = task['default_timezone'] || DEFAULT_TIMEZONE
          schema.map do |column|
            column_name   = column[:name]
            embulk_type   = column[:type]
            column_option = column_options_map[column_name] || {}
            scale         = column_option['scale'] || DEFAULT_SCALE
            self.new(
              embulk_type, column_option['type'],
              timestamp_format: column_option['timestamp_format'],
              timezone: column_option['timezone'],
              strict: column_option['strict'],
              default_timestamp_format: default_timestamp_format,
              default_timezone: default_timezone,
              scale: scale,
              fields: column_option['fields']
            ).create_converter
          end
        end

        attr_reader :embulk_type, :type, :timestamp_format, :timezone, :zone_offset, :strict

        def initialize(
          embulk_type, type = nil,
          timestamp_format: nil, timezone: nil, strict: nil,
          default_timestamp_format: DEFAULT_TIMESTAMP_FORMAT,
          default_timezone: DEFAULT_TIMEZONE,
          scale: DEFAULT_SCALE,
          fields: nil
        )
          @embulk_type      = embulk_type
          @type             = (type || Helper.bq_type_from_embulk_type(embulk_type)).upcase
          @timestamp_format = timestamp_format
          @default_timestamp_format = default_timestamp_format
          @default_timezone = default_timezone
          @timezone         = timezone || default_timezone
          @zone_offset      = TimeWithZone.zone_offset(@timezone)
          @strict           = strict.nil? ? true : strict
          @scale            = scale
          @fields           = fields
        end

        def create_converter
          case embulk_type
          when :boolean   then boolean_converter
          when :long      then long_converter
          when :double    then double_converter
          when :string    then string_converter
          when :timestamp then timestamp_converter
          when :json      then json_converter
          else raise NotSupportedType, "embulk type #{embulk_type} is not supported"
          end
        end

        def with_typecast_error(val)
          begin
            yield(val)
          rescue => e
            raise_typecast_error(val)
          end
        end

        def raise_typecast_error(val)
          message = "cannot cast #{@embulk_type} `#{val}` to #{@type}"
          if @strict
            raise TypeCastError, message
          else
            Embulk.logger.trace { message }
            return nil
          end
        end

        def boolean_converter
          case type
          when 'BOOLEAN'
            Proc.new {|val|
              val
            }
          when 'STRING'
            Proc.new {|val|
              next nil if val.nil?
              val.to_s
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for boolean column"
          end
        end

        def long_converter
          case type
          when 'BOOLEAN'
            Proc.new {|val|
              next nil if val.nil?
              next true if val == 1
              next false if val == 0
              raise_typecast_error(val)
            }
          when 'INTEGER'
            Proc.new {|val|
              val
            }
          when 'FLOAT'
            Proc.new {|val|
              next nil if val.nil?
              val.to_f
            }
          when 'STRING'
            Proc.new {|val|
              next nil if val.nil?
              val.to_s
            }
          when 'TIMESTAMP'
            Proc.new {|val|
              next nil if val.nil?
              val # BigQuery supports UNIX timestamp
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for long column"
          end
        end

        def double_converter
          case type
          when 'INTEGER'
            Proc.new {|val|
              next nil if val.nil?
              val.to_i
            }
          when 'FLOAT'
            Proc.new {|val|
              val
            }
          when 'STRING'
            Proc.new {|val|
              next nil if val.nil?
              val.to_s
            }
          when 'TIMESTAMP'
            Proc.new {|val|
              next nil if val.nil?
              val # BigQuery supports UNIX timestamp
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for double column"
          end
        end

        def string_converter
          case type
          when 'BOOLEAN'
            Proc.new {|val|
              next nil if val.nil?
              next true if (val == true) || (val == 'true'.freeze)
              next false if (val == false) || (val == 'false'.freeze)
              raise_typecast_error(val)
            }
          when 'INTEGER'
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                Integer(val)
              end
            }
          when 'FLOAT'
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                Float(val)
              end
            }
          when 'STRING'
            Proc.new {|val|
              val
            }
          when 'TIMESTAMP'
            if @timestamp_format
              Proc.new {|val|
                next nil if val.nil?
                with_typecast_error(val) do |val|
                  TimeWithZone.set_zone_offset(Time.strptime(val, @timestamp_format), zone_offset).strftime("%Y-%m-%d %H:%M:%S.%6N %:z")
                end
              }
            else
              Proc.new {|val|
                next nil if val.nil?
                val # Users must care of BQ timestamp format
              }
            end
          when 'DATE'
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                TimeWithZone.set_zone_offset(Time.parse(val), zone_offset).strftime("%Y-%m-%d")
              end
            }
          when 'DATETIME'
            if @timestamp_format
              Proc.new {|val|
                next nil if val.nil?
                with_typecast_error(val) do |val|
                  Time.strptime(val, @timestamp_format).strftime("%Y-%m-%d %H:%M:%S.%6N")
                end
              }
            else
              Proc.new {|val|
                next nil if val.nil?
                val # Users must care of BQ timestamp format
              }
            end
          when 'TIME'
            # TimeWithZone doesn't affect any change to the time value
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                TimeWithZone.set_zone_offset(Time.parse(val), zone_offset).strftime("%H:%M:%S.%6N")
              end
            }
          when 'RECORD'
            record_field_converters = build_record_field_converters
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                parsed = JSON.parse(val)
                apply_field_converters(parsed, record_field_converters)
              end
            }
          when 'NUMERIC'
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                BigDecimal(val.to_s).round(@scale, BigDecimal::ROUND_CEILING)
              end
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for string column"
          end
        end

        def timestamp_converter
          case type
          when 'INTEGER'
            Proc.new {|val|
              next nil if val.nil?
              val.to_i
            }
          when 'FLOAT'
            Proc.new {|val|
              next nil if val.nil?
              val.to_f
            }
          when 'STRING'
            _timestamp_format = @timestamp_format || @default_timestamp_format
            Proc.new {|val|
              next nil if val.nil?
              with_typecast_error(val) do |val|
                val.localtime(zone_offset).strftime(_timestamp_format)
              end
            }
          when 'TIMESTAMP'
            Proc.new {|val|
              next nil if val.nil?
              val.strftime("%Y-%m-%d %H:%M:%S.%6N %:z")
            }
          when 'DATE'
            Proc.new {|val|
              next nil if val.nil?
              val.localtime(zone_offset).strftime("%Y-%m-%d")
            }
          when 'DATETIME'
            Proc.new {|val|
              next nil if val.nil?
              val.localtime(zone_offset).strftime("%Y-%m-%d %H:%M:%S.%6N")
            }
          when 'TIME'
            Proc.new {|val|
              next nil if val.nil?
              val.localtime(zone_offset).strftime("%H:%M:%S.%6N")
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for timestamp column"
          end
        end

        def json_converter
          case type
          when 'STRING'
            Proc.new {|val|
              next nil if val.nil?
              val.to_json
            }
          when 'RECORD'
            record_field_converters = build_record_field_converters
            Proc.new {|val|
              next nil if val.nil?
              apply_field_converters(val, record_field_converters)
            }
          when 'JSON'
            Proc.new {|val|
              val
            }
          else
            raise NotSupportedType, "cannot take column type #{type} for json column"
          end
        end

        def build_record_field_converters
          return {} unless @fields.is_a?(Array) && !@fields.empty?

          converters = {}
          @fields.each do |field_config|
            name = field_config['name']
            type = field_config['type'].upcase
            mode = (field_config['mode'] || 'NULLABLE').upcase
            # Nested RECORD values are already Hashes from JSON.parse, use :json
            # Other values come as strings/primitives from JSON, use :string
            source_type = ['RECORD', 'JSON'].include?(type) ? :json : :string

            converter = self.class.new(
              source_type, type,
              timestamp_format: field_config['timestamp_format'],
              timezone: field_config['timezone'],
              strict: @strict,
              default_timestamp_format: @default_timestamp_format,
              default_timezone: @default_timezone,
              scale: @scale,
              fields: field_config['fields']
            ).create_converter

            if mode == 'REPEATED'
              converters[name] = Proc.new {|val|
                next nil if val.nil?
                val.map {|v| converter.call(v) }
              }
            else
              converters[name] = converter
            end
          end
          converters
        end

        def apply_field_converters(data, field_converters)
          return data if field_converters.empty?

          if data.is_a?(Array)
            data.map {|element| apply_field_converters(element, field_converters) }
          elsif data.is_a?(Hash)
            field_converters.each do |name, converter|
              data[name] = converter.call(data[name]) if data.key?(name)
            end
            data
          else
            data
          end
        end
      end
    end
  end
end
