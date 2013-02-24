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

# Takes an array of split iptables arguments and parses them returning a hash
def parse_shell_split(split)
  # Resultant hash
  hash = {
    :split => split,
    :parameters => {},
    :matches => [],
    :chain => nil,
    :target_options => {},
  }

  # First two parameters should be -A CHAIN
  raise UnparseableSplit, "First argument [#{split[0]}] in line is not -A" if split[0] != "-A"
  raise UnparseableSplit, "Second argument [#{split[1]}] in line is not a word" if split[1] !~ /^\w+/

  # Load the chain into our hash
  hash[:chain] = split[1]

  # Remove those elements, we are done with them
  split.shift(2)

  # Now iterate across the rest, here we set some initial states
  negate = false
  match = false
  target = false
  switch = nil
  match_name = nil
  match_hash = nil

  split.each do |p|
    if p == "!"
      # Hit a negative? Negate that sucker
      negate = true
    elsif p == '-m'
      raise UnparseableSplit, "Cannot negate a match declaration" if negate
      # Hit a match
      match = true
    elsif p == '-j'
      raise UnparseableSplit, "Cannot negate a jump" if negate

      # Close off any other switches
      if switch
        if match
          raise UnparseableSplit, "Found a -j, previous switch was a match but not match_name" unless match_name

          match_hash ||= {}
          match_hash[:name] = match_name
          match_hash[:options] ||= {}
          match_hash[:options][switch] = true
          hash[:matches] << match_hash
        else
          hash[:parameters][switch] = true
        end
      end

      target = true
      # Reset some states
      match = false
      match_name = nil
      switch = nil
    else
      # Its probably a value lets sum it all up
      if match
        raise UnparseableSplit, "Cannot negate a match name" if negate
        # The value is the name of the matcher
        match_name = p
      else
        # Looks like a value
      end

      # Reset some states
      negate = false
      match = false
      switch = nil
    end
  end

  hash
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
  begin
    parse_shell_split(ss)
  rescue UnparseableSplit => e
    raise UnparseableLine, "Cannot parse line [#{line}] because [#{e.message}]"
  end
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
File.open('sample-iptables-save') do |f|
  hash = parse_iptables_save(f.read)
end

pp hash
