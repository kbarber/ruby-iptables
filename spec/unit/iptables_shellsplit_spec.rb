require 'spec_helper'

describe 'Iptables#shellsplit' do
  let(:ipt) do
    Iptables.new
  end

  tests = [
    {:name => "basic 1",
     :input => "-A INPUT -s 1.1.1.2/32 -j CHECKSUM --checksum-fill \n",
     :output => ["-A", "INPUT", "-s", "1.1.1.2/32", "-j", "CHECKSUM", "--checksum-fill"]},
    {:name => "with negation",
     :input => "-A INPUT -s 1.1.1.1/32 -p tcp -m tos ! --tos 0x05/0x06 \n",
     :output => ["-A", "INPUT", "-s", "1.1.1.1/32", "-p", "tcp", "-m", "tos", "!", "--tos", "0x05/0x06"]},
    {:name => "with quotes",
     :input => "-A INPUT -p sctp -m string ! --string \"00BBCC\" --algo bm --to 65535 \n",
     :output => ["-A", "INPUT", "-p", "sctp", "-m", "string", "!", "--string", "00BBCC", "--algo", "bm", "--to", "65535"]},
    {:name => "with quotes 2",
     :input => "-A INPUT -p tcp -m comment --comment \"000 foo\" -j ACCEPT \n",
     :output => ["-A", "INPUT", "-p", "tcp", "-m", "comment", "--comment", "000 foo", "-j", "ACCEPT" ]},
  ]
  tests.each do |t|
    it "run sample test [#{t[:name]}]" do
      ipt.shellsplit(t[:input]).should eq t[:output]
    end
  end
end
