#!/usr/bin/env ruby

require 'pp'

# Base class for iptables parser exceptions
class IptablesParserException < Exception
end

# Indicates a line was parsed but no prior table was declared
class NoTable < IptablesParserException
end

# Raised if the line cannot be parsed
class UnparseableLine < IptablesParserException
end

# Raised if the split cannot be parsed
class UnparseableSplit < IptablesParserException
end

# Debug output
def debug(text)
  puts "D, #{text}"
end

# Takes a split array, and finds switches and arguments. It returns a hash with
# switches on the LHS, and values on the right. Values appear as arrays.
#
# For switches without values, the RHS will just be the boolean `true`.
def hash_switches_and_values(split)
  result = []

  current = nil

  split.each do |p|
    # TODO: search for conmark from results, something still fucked up here
    if p =~ /^--?(.+)/
      if current and !current.empty?
        unless current[:negate]
          result << current
          current = {}
        end
      else
        current = {}
      end
      current[:switch] = $1
    elsif p == '!'
      if current
        result << current
      end
      current = {}
      current[:negate] = true
    else
      raise "Found a value without corresponding arg" unless current
      current[:values] ||= []
      current[:values] << p
    end
  end
  result << current

  result
end

# Break rule line into pices like a shell, stolen from ruby core
# http://svn.ruby-lang.org/repos/ruby/trunk/lib/shellwords.rb
def shellsplit(line)
  words = []
  field = ''
  line.scan(/\G\s*(?>([^\s\\\'\"]+)|'([^\']*)'|"((?:[^\"\\]|\\.)*)"|(\\.?)|(\S))(\s|\z)?/m) do
    |word, sq, dq, esc, garbage, sep|
    raise ArgumentError, "Unmatched double quote: #{line.inspect}" if garbage
    field << (word || sq || (dq || esc).gsub(/\\(.)/, '\\1'))
    if sep
      words << field
      field = ''
    end
  end
  words
end

# Parses an append line return a hash
def parse_append_line(line)
  ss = shellsplit(line)
  {
    :shell_split => ss,
    :split_args => hash_switches_and_values(ss),
  }
end

# Takes raw iptables-save input, returns a data hash
def parse_iptables_save(text)
  # Set the table to nil to begin with so we can detect append lines with no
  # prior table decleration.
  table = nil

  # Input line number for debugging later
  original_line_number = 0

  # Hash for storing the final result
  hash = {}

  text.each_line do |line|

    # If we find a table declaration, change table
    if line =~ /^*([a-z]+)$/
      table = $1
      debug("Found table [#{table}] on line [#{original_line_number}]")
    end

    # If we find an append line, parse it
    if line =~ /^-A (\S+)/
      raise NoTable, "Found an append line [#{line}] on line [#{input_line}], but no table yet" if table.nil?

      chain = $1
      line_hash = parse_append_line(line)

      line_hash[:source] = {
        :original_line => line,
        :original_line_number => original_line_number,
      }

      hash[table] ||= {}
      hash[table][chain] ||= {}
      hash[table][chain][:rules] ||= []
      hash[table][chain][:rules] << line_hash
    end

    original_line_number += 1
  end

  hash
end

hash = {}
File.open('sample-iptables-save2') do |f|
  hash = parse_iptables_save(f.read)
end

pp hash
