require 'spec_helper'

describe 'Iptables#switch_hash' do
  let(:ipt) do
    Iptables.new
  end

  tests = [
    {:name => "basic 1",
     :input => ["-A", "OUTPUT", "-s", "1.1.1.2/32", "-j", "CLASSIFY", "--set-class", "0004:0056"],
     :output => [
      {:values=>["OUTPUT"], :switch=>"A"},
      {:values=>["1.1.1.2/32"], :switch=>"s"},
      {:values=>["CLASSIFY"], :switch=>"j"},
      {:values=>["0004:0056"], :switch=>"set-class"}]},
    {:name => "negate 1",
     :input => ["-A", "OUTPUT", "!", "-o", "eth0"],
     :output => [
       {:values=>["OUTPUT"], :switch=>"A"},
       {:negate=>true, :values=>["eth0"], :switch=>"o"}]},
    {:name => "multivalues 1",
     :input => ["-A", "INPUT", "-s", "1.1.1.1/32", "-p", "tcp", "-m", "tcp", "!", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN"],
     :output => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["1.1.1.1/32"], :switch=>"s"},
       {:values=>["tcp"], :switch=>"p"},
       {:values=>["tcp"], :switch=>"m"},
       {:negate=>true, :values=>["FIN,SYN,RST,ACK", "SYN"], :switch=>"tcp-flags"}]},
    {:name => "complex 1",
     :input => ["-A", "INPUT", "-p", "ah", "-m", "ah", "!", "--ahspi", "1", "-m", "connmark", "--mark", "0x3/0x1", "-m", "ah", "--ahspi", "3", "-m", "connmark", "!", "--mark", "0x18/0x1"],
     :output => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["ah"], :switch=>"p"},
       {:values=>["ah"], :switch=>"m"},
       {:negate=>true, :values=>["1"], :switch=>"ahspi"},
       {:values=>["connmark"], :switch=>"m"},
       {:values=>["0x3/0x1"], :switch=>"mark"},
       {:values=>["ah"], :switch=>"m"},
       {:values=>["3"], :switch=>"ahspi"},
       {:values=>["connmark"], :switch=>"m"},
       {:negate=>true, :values=>["0x18/0x1"], :switch=>"mark"}]},
    {:name => "complex 2",
     :input => ["-A", "INPUT", "-s", "1.1.1.1/32", "-m", "connbytes", "!", "--connbytes", "10:1000", "--connbytes-mode", "packets", "--connbytes-dir", "both"],
     :output => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["1.1.1.1/32"], :switch=>"s"},
       {:values=>["connbytes"], :switch=>"m"},
       {:negate=>true, :values=>["10:1000"], :switch=>"connbytes"},
       {:values=>["packets"], :switch=>"connbytes-mode"},
       {:values=>["both"], :switch=>"connbytes-dir"}]},
    {:name => "space args 1",
     :input => ["-A", "INPUT", "-p", "tcp", "-m", "comment", "--comment", "000 foo", "-j", "ACCEPT"],
     :output => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["tcp"], :switch=>"p"},
       {:values=>["comment"], :switch=>"m"},
       {:values=>["000 foo"], :switch=>"comment"},
       {:values=>["ACCEPT"], :switch=>"j"}]},
  ]
  tests.each do |t|
    it "run sample test [#{t[:name]}]" do
      ipt.switch_hash(t[:input]).should eq t[:output]
    end
  end
end
