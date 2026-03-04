require_relative './helper'
require 'embulk/output/bigquery/value_converter_factory'

module Embulk
  class Output::Bigquery
    class TestValueConverterFactory < Test::Unit::TestCase

      class TestCreateConverters < Test::Unit::TestCase
        def test_create_default_converter
          schema = Schema.new([
            Column.new({index: 0, name: 'boolean', type: :boolean}),
            Column.new({index: 1, name: 'long', type: :long}),
            Column.new({index: 2, name: 'double', type: :double}),
            Column.new({index: 3, name: 'string', type: :string}),
            Column.new({index: 4, name: 'timestamp', type: :timestamp}),
            Column.new({index: 5, name: 'json', type: :json}),
          ])
          converters = ValueConverterFactory.create_converters({}, schema)
          assert_equal schema.size, converters.size
          # Check correct converters are created
          # Proc can not have names, so we have to execute to check...
          assert_equal true, converters[0].call(true)
          assert_equal 1, converters[1].call(1)
          assert_equal 1.1, converters[2].call(1.1)
          assert_equal 'foo', converters[3].call('foo')
          timestamp = Time.parse("2016-02-26 00:00:00.500000 +00:00")
          assert_equal "2016-02-26 00:00:00.500000 +00:00", converters[4].call(timestamp)
          assert_equal %Q[{"foo":"foo"}], converters[5].call({'foo'=>'foo'})
        end

        def test_create_custom_converter
          schema = Schema.new([
            Column.new({index: 0, name: 'boolean', type: :boolean}),
            Column.new({index: 1, name: 'long', type: :long}),
            Column.new({index: 2, name: 'double', type: :double}),
            Column.new({index: 3, name: 'string', type: :string}),
            Column.new({index: 4, name: 'timestamp', type: :timestamp}),
            Column.new({index: 5, name: 'json', type: :json}),
          ])
          task = {
            'column_options' => [
              {'name' => 'boolean',   'type' => 'STRING'},
              {'name' => 'long',      'type' => 'STRING'},
              {'name' => 'double',    'type' => 'STRING'},
              {'name' => 'string',    'type' => 'INTEGER'},
              {'name' => 'timestamp', 'type' => 'INTEGER'},
              {'name' => 'json',      'type' => 'RECORD'},
            ],
          }
          converters = ValueConverterFactory.create_converters(task, schema)
          assert_equal schema.size, converters.size
          # Check correct converters are created
          # Proc can not have names, so we have to execute to check...
          assert_equal 'true', converters[0].call(true)
          assert_equal '1', converters[1].call(1)
          assert_equal '1.1', converters[2].call(1.1)
          assert_equal 1, converters[3].call('1')
          timestamp = Time.parse("2016-02-26 00:00:00.100000 +00:00")
          assert_equal 1456444800, converters[4].call(timestamp)
          assert_equal({'foo'=>'foo'}, converters[5].call({'foo'=>'foo'}))
        end
      end

      class TestBooleanConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :boolean

        def test_boolean
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal true, converter.call(true)
          assert_equal false, converter.call(false)
        end

        def test_integer
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter }
        end

        def test_float
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter }
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "true", converter.call(true)
          assert_equal "false", converter.call(false)
        end

        def test_timestamp
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter }
        end

        def test_date
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter }
        end

        def test_datetime
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATETIME').create_converter }
        end

        def test_record
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter }
        end
      end

      class TestLongConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :long

        def test_boolean
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal true, converter.call(1)
          assert_equal false, converter.call(0)
          assert_raise { converter.call(2) }
        end

        def test_integer
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1, converter.call(1)
        end

        def test_float
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1.0, converter.call(1)
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "1", converter.call(1)
        end

        def test_timestamp
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1408452095, converter.call(1408452095)
        end

        def test_date
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter }
        end

        def test_datetime
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATETIME').create_converter }
        end

        def test_record
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter }
        end
      end

      class TestDoubleConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :double

        def test_boolean
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter }
        end

        def test_integer
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1, converter.call(1.1)
        end

        def test_float
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1.1, converter.call(1.1)
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "1.1", converter.call(1.1)
        end

        def test_timestamp
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1408452095.188766, converter.call(1408452095.188766)
        end

        def test_date
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter }
        end

        def test_datetime
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATETIME').create_converter }
        end

        def test_record
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter }
        end
      end

      class TestStringConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :string

        def test_boolean
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal true, converter.call('true')
          assert_equal false, converter.call('false')
          assert_raise { converter.call('foo') }
        end

        def test_integer
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1, converter.call('1')
          assert_raise { converter.call('1.1') }
        end

        def test_float
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal 1.1, converter.call('1.1')
          assert_raise { converter.call('foo') }
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "foo", converter.call("foo")
        end

        def test_timestamp
          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'TIMESTAMP',
            timestamp_format: '%Y-%m-%d', timezone: 'Asia/Tokyo'
          ).create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "2016-02-26 00:00:00.000000 +09:00", converter.call("2016-02-26")

          # Users must care of BQ timestamp format by themselves with no timestamp_format
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "2016-02-26 00:00:00", converter.call("2016-02-26 00:00:00")
        end

        def test_date
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "2016-02-26", converter.call("2016-02-26")
          assert_equal "2016-02-26", converter.call("2016-02-26 00:00:00")
          assert_raise { converter.call('foo') }
        end

        def test_datetime
          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'DATETIME',
            timestamp_format: '%Y/%m/%d'
          ).create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "2016-02-26 00:00:00.000000", converter.call("2016/02/26")

          # Users must care of BQ datetime format by themselves with no timestamp_format
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'DATETIME').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "2016-02-26 00:00:00", converter.call("2016-02-26 00:00:00")
        end

        def test_time
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIME').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal "00:03:22.000000", converter.call("00:03:22")
          assert_equal "15:22:00.000000", converter.call("3:22 PM")
          assert_equal "03:22:00.000000", converter.call("3:22 AM")
          assert_equal "00:00:00.000000", converter.call("2016-02-26 00:00:00")

           # TimeWithZone doesn't affect any change to the time value
          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'TIME', timezone: 'Asia/Tokyo'
          ).create_converter
          assert_equal "15:00:01.000000", converter.call("15:00:01")

          assert_raise { converter.call('foo') }
        end

        def test_record
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter
          assert_equal({'foo'=>'foo'}, converter.call(%Q[{"foo":"foo"}]))
          assert_raise { converter.call('foo') }
        end
      end

      class TestTimestampConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :timestamp

        def test_boolean
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter }
        end

        def test_integer
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter
          assert_equal nil, converter.call(nil)
          expected = 1456444800
          assert_equal expected, converter.call(Time.at(expected))
        end

        def test_float
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter
          assert_equal nil, converter.call(nil)
          expected = 1456444800.500000
          assert_equal expected, converter.call(Time.at(expected))
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-26 00:00:00.500000 +00:00")
          expected = "2016-02-26 00:00:00.500000"
          assert_equal expected, converter.call(timestamp)

          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'STRING',
            timestamp_format: '%Y-%m-%d', timezone: 'Asia/Tokyo'
          ).create_converter
          timestamp = Time.parse("2016-02-25 15:00:00.500000 +00:00")
          expected = "2016-02-26"
          assert_equal expected, converter.call(timestamp)
        end

        def test_timestamp
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter
          assert_equal nil, converter.call(nil)
          subject = 1456444800.500000
          expected = "2016-02-26 00:00:00.500000 +00:00"
          assert_equal expected, converter.call(Time.at(subject).utc)
        end

        def test_date
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-26 00:00:00.500000 +00:00")
          expected = "2016-02-26"
          assert_equal expected, converter.call(timestamp)

          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'DATE', timezone: 'Asia/Tokyo'
          ).create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-25 15:00:00.500000 +00:00")
          expected = "2016-02-26"
          assert_equal expected, converter.call(timestamp)

          assert_raise { converter.call('foo') }
        end

        def test_datetime
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'DATETIME').create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-26 00:00:00.500000 +00:00")
          expected = "2016-02-26 00:00:00.500000"
          assert_equal expected, converter.call(timestamp)

          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'DATETIME', timezone: 'Asia/Tokyo'
          ).create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-25 15:00:00.500000 +00:00")
          expected = "2016-02-26 00:00:00.500000"
          assert_equal expected, converter.call(timestamp)

          assert_raise { converter.call('foo') }
        end

        def test_time
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'TIME').create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-26 00:00:00.500000 +00:00")
          expected = "00:00:00.500000"
          assert_equal expected, converter.call(timestamp)

          converter = ValueConverterFactory.new(
            SCHEMA_TYPE, 'TIME', timezone: 'Asia/Tokyo'
          ).create_converter
          assert_equal nil, converter.call(nil)
          timestamp = Time.parse("2016-02-25 15:00:00.500000 +00:00")
          expected = "00:00:00.500000"
          assert_equal expected, converter.call(timestamp)

          assert_raise { converter.call('foo') }
        end

        def test_record
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter }
        end
      end

      class TestJsonConverter < Test::Unit::TestCase
        SCHEMA_TYPE = :json

        def test_boolean
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'BOOLEAN').create_converter }
        end

        def test_integer
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'INTEGER').create_converter }
        end

        def test_float
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'FLOAT').create_converter }
        end

        def test_string
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'STRING').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal(%Q[{"foo":"foo"}], converter.call({'foo'=>'foo'}))
        end

        def test_timestamp
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'TIMESTAMP').create_converter }
        end

        def test_date
          assert_raise { ValueConverterFactory.new(SCHEMA_TYPE, 'DATE').create_converter }
        end

        def test_record
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'RECORD').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal({'foo'=>'foo'}, converter.call({'foo'=>'foo'}))
        end

        def test_json
          converter = ValueConverterFactory.new(SCHEMA_TYPE, 'JSON').create_converter
          assert_equal nil, converter.call(nil)
          assert_equal({'foo'=>'foo'}, converter.call({'foo'=>'foo'}))
        end
      end

      def test_strict_false
        converter = ValueConverterFactory.new(:string, 'BOOLEAN', strict: false).create_converter
        assert_equal nil, converter.call('foo')

        converter = ValueConverterFactory.new(:string, 'INTEGER', strict: false).create_converter
        assert_equal nil, converter.call('foo')
      end

      class TestRecordFieldConverters < Test::Unit::TestCase
        def build_converter(source_type, fields)
          ValueConverterFactory.new(source_type, 'RECORD', fields: fields).create_converter
        end

        # 1. ソース型別の基本動作

        def test_string_to_record_with_fields
          fields = [
            {'name' => 'key', 'type' => 'STRING', 'mode' => 'NULLABLE'},
            {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
          ]
          converter = build_converter(:string, fields)

          result = converter.call('{"key":"val","ts":"2024-01-15T10:30:00"}')
          assert_equal 'val', result['key']
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result['ts']
        end

        def test_json_to_record_with_fields
          fields = [
            {'name' => 'key', 'type' => 'STRING', 'mode' => 'NULLABLE'},
            {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
          ]
          converter = build_converter(:json, fields)

          result = converter.call({'key' => 'val', 'ts' => '2024-01-15T10:30:00'})
          assert_equal 'val', result['key']
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result['ts']
        end

        def test_nil_input
          fields = [
            {'name' => 'key', 'type' => 'STRING', 'mode' => 'NULLABLE'},
          ]
          assert_equal nil, build_converter(:string, fields).call(nil)
          assert_equal nil, build_converter(:json, fields).call(nil)
        end

        # 2. フィールド型別（JSON.parse後のRubyネイティブ型が入力）

        def test_field_type_string
          fields = [{'name' => 'v', 'type' => 'STRING', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":"hello"}')
          assert_equal 'hello', result['v']
        end

        def test_field_type_integer
          fields = [{'name' => 'v', 'type' => 'INTEGER', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":42}')
          assert_equal 42, result['v']
        end

        def test_field_type_float
          fields = [{'name' => 'v', 'type' => 'FLOAT', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":3.14}')
          assert_equal 3.14, result['v']
        end

        def test_field_type_boolean
          fields = [{'name' => 'v', 'type' => 'BOOLEAN', 'mode' => 'NULLABLE'}]
          converter = build_converter(:string, fields)

          result = converter.call('{"v":true}')
          assert_equal true, result['v']

          result = converter.call('{"v":false}')
          assert_equal false, result['v']
        end

        def test_field_type_timestamp_with_format
          fields = [{'name' => 'v', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15T10:30:00"}')
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result['v']
        end

        def test_field_type_timestamp_without_format
          fields = [{'name' => 'v', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15 10:30:00"}')
          assert_equal '2024-01-15 10:30:00', result['v']
        end

        def test_field_type_date
          fields = [{'name' => 'v', 'type' => 'DATE', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15 10:30:00"}')
          assert_equal '2024-01-15', result['v']
        end

        def test_field_type_datetime_with_format
          fields = [{'name' => 'v', 'type' => 'DATETIME', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y/%m/%d %H:%M:%S'}]
          result = build_converter(:string, fields).call('{"v":"2024/01/15 10:30:00"}')
          assert_equal '2024-01-15 10:30:00.000000', result['v']
        end

        def test_field_type_datetime_without_format
          fields = [{'name' => 'v', 'type' => 'DATETIME', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15 10:30:00"}')
          assert_equal '2024-01-15 10:30:00', result['v']
        end

        def test_field_type_time
          fields = [{'name' => 'v', 'type' => 'TIME', 'mode' => 'NULLABLE'}]
          result = build_converter(:string, fields).call('{"v":"15:30:00"}')
          assert_equal '15:30:00.000000', result['v']
        end

        # 3. オプション（timezone）

        def test_field_timestamp_with_timezone
          fields = [{'name' => 'v', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%d', 'timezone' => 'Asia/Tokyo'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15"}')
          assert_equal '2024-01-15 00:00:00.000000 +09:00', result['v']
        end

        def test_field_timestamp_without_timezone_uses_default
          fields = [{'name' => 'v', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%d'}]
          result = build_converter(:string, fields).call('{"v":"2024-01-15"}')
          assert_equal '2024-01-15 00:00:00.000000 +00:00', result['v']
        end

        # 4. mode

        def test_repeated_string
          fields = [{'name' => 'v', 'type' => 'STRING', 'mode' => 'REPEATED'}]
          result = build_converter(:string, fields).call('{"v":["a","b","c"]}')
          assert_equal ['a', 'b', 'c'], result['v']
        end

        def test_repeated_timestamp
          fields = [{'name' => 'v', 'type' => 'TIMESTAMP', 'mode' => 'REPEATED', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'}]
          result = build_converter(:string, fields).call('{"v":["2024-01-15T10:30:00","2024-02-20T15:00:00"]}')
          assert_equal [
            '2024-01-15 10:30:00.000000 +00:00',
            '2024-02-20 15:00:00.000000 +00:00',
          ], result['v']
        end

        def test_repeated_nil
          fields = [{'name' => 'v', 'type' => 'STRING', 'mode' => 'REPEATED'}]
          result = build_converter(:string, fields).call('{"v":null}')
          assert_equal nil, result['v']
        end

        # 5. 再帰（ネストRECORD）

        def test_nested_record
          fields = [
            {'name' => 'inner', 'type' => 'RECORD', 'mode' => 'NULLABLE', 'fields' => [
              {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S', 'timezone' => 'Asia/Tokyo'},
            ]},
          ]
          result = build_converter(:string, fields).call('{"inner":{"ts":"2024-01-15T10:30:00"}}')
          assert_equal '2024-01-15 10:30:00.000000 +09:00', result['inner']['ts']
        end

        def test_repeated_nested_record
          fields = [
            {'name' => 'items', 'type' => 'RECORD', 'mode' => 'REPEATED', 'fields' => [
              {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
            ]},
          ]
          result = build_converter(:string, fields).call('{"items":[{"ts":"2024-01-15T10:30:00"},{"ts":"2024-02-20T15:00:00"}]}')
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result['items'][0]['ts']
          assert_equal '2024-02-20 15:00:00.000000 +00:00', result['items'][1]['ts']
        end

        # 6. エッジケース

        def test_record_without_fields
          converter = ValueConverterFactory.new(:string, 'RECORD').create_converter
          assert_equal({'foo' => 'bar'}, converter.call('{"foo":"bar"}'))
        end

        def test_field_missing_in_data
          fields = [
            {'name' => 'key', 'type' => 'STRING', 'mode' => 'NULLABLE'},
            {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
          ]
          result = build_converter(:string, fields).call('{"key":"hello"}')
          assert_equal 'hello', result['key']
          assert_false result.key?('ts')
        end

        def test_top_level_data_is_array
          fields = [
            {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
          ]
          result = build_converter(:string, fields).call('[{"ts":"2024-01-15T10:30:00"},{"ts":"2024-02-20T15:00:00"}]')
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result[0]['ts']
          assert_equal '2024-02-20 15:00:00.000000 +00:00', result[1]['ts']
        end

        # 7. 統合テスト

        def test_create_converters_with_record_fields
          schema = Schema.new([
            Column.new({index: 0, name: 'data', type: :json}),
          ])
          task = {
            'column_options' => [
              {
                'name' => 'data',
                'type' => 'RECORD',
                'fields' => [
                  {'name' => 'ts', 'type' => 'TIMESTAMP', 'mode' => 'NULLABLE', 'timestamp_format' => '%Y-%m-%dT%H:%M:%S'},
                  {'name' => 'key', 'type' => 'STRING', 'mode' => 'NULLABLE'},
                ],
              },
            ],
          }
          converters = ValueConverterFactory.create_converters(task, schema)

          result = converters[0].call({'ts' => '2024-01-15T10:30:00', 'key' => 'hello'})
          assert_equal '2024-01-15 10:30:00.000000 +00:00', result['ts']
          assert_equal 'hello', result['key']
        end
      end

    end
  end
end
