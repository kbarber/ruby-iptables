require 'spec_helper'

describe 'Iptables::Decoder#rule_hash' do
  subject do
    Iptables::Decoder.new
  end

  tests = [
    {:name => "basic destination option 1",
     :input => [
      {:values=>["OUTPUT"], :switch=>"A"},
      {:values=>["1.1.1.2/32"], :switch=>"s"},
      {:values=>["CLASSIFY"], :switch=>"j"},
      {:values=>["0004:0056"], :switch=>"set-class"}],
     :output => {
       :chain => "OUTPUT",
       :parameters => {
         "s" => ["1.1.1.2/32"],
       },
       :matches => [],
       :target => "CLASSIFY",
       :target_options => {
         "set-class" => ["0004:0056"],
       },
     }},
    {:name => "negate parameter 1",
     :input => [
       {:values=>["OUTPUT"], :switch=>"A"},
       {:negate=>true, :values=>["eth0"], :switch=>"o"}],
     :output => {
       :chain => "OUTPUT",
       :parameters => {
         "!o" => ["eth0"],
       },
       :matches => [],
       :target => nil,
       :target_options => {},
     }},
    {:name => "match with options 1",
     :input => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["1.1.1.1/32"], :switch=>"s"},
       {:values=>["tcp"], :switch=>"p"},
       {:values=>["tcp"], :switch=>"m"},
       {:negate=>true, :values=>["FIN,SYN,RST,ACK", "SYN"], :switch=>"tcp-flags"}],
     :output => {
       :chain => "INPUT",
       :parameters => {
         "s" => ["1.1.1.1/32"],
         "p" => ["tcp"],
       },
       :matches => [
         {:name => "tcp",
          :options => {
            "!tcp-flags" => ["FIN,SYN,RST,ACK", "SYN"],
          }},
       ],
       :target => nil,
       :target_options => {},
     }},
    {:name => "match with options 2",
     :input => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["tcp"], :switch=>"p"},
       {:values=>["comment"], :switch=>"m"},
       {:values=>["000 foo"], :switch=>"comment"},
       {:values=>["ACCEPT"], :switch=>"j"}],
     :output => {
       :chain => "INPUT",
       :parameters => {
         "p" => ["tcp"],
       },
       :target => "ACCEPT",
       :matches => [
         {:name => "comment",
          :options => {
            "comment" => ["000 foo"],
          }},
       ],
       :target => "ACCEPT",
       :target_options => {},
     }},
    {:name => "complex 1",
     :input => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["ah"], :switch=>"p"},
       {:values=>["ah"], :switch=>"m"},
       {:negate=>true, :values=>["1"], :switch=>"ahspi"},
       {:values=>["connmark"], :switch=>"m"},
       {:values=>["0x3/0x1"], :switch=>"mark"},
       {:values=>["ah"], :switch=>"m"},
       {:values=>["3"], :switch=>"ahspi"},
       {:values=>["connmark"], :switch=>"m"},
       {:negate=>true, :values=>["0x18/0x1"], :switch=>"mark"}],
     :output => {
       :chain => "INPUT",
       :parameters => {
         "p" => ["ah"],
       },
       :matches => [
         {:name => "ah",
          :options => {
            "!ahspi" => ["1"],
          }},
         {:name => "connmark",
          :options => {
            "mark" => ["0x3/0x1"],
          }},
         {:name => "ah",
          :options => {
            "ahspi" => ["3"],
          }},
         {:name => "connmark",
          :options => {
            "!mark" => ["0x18/0x1"],
          }},
       ],
       :target => nil,
       :target_options => {},
     }},
    {:name => "complex 2",
     :input => [
       {:values=>["INPUT"], :switch=>"A"},
       {:values=>["1.1.1.1/32"], :switch=>"s"},
       {:values=>["connbytes"], :switch=>"m"},
       {:negate=>true, :values=>["10:1000"], :switch=>"connbytes"},
       {:values=>["packets"], :switch=>"connbytes-mode"},
       {:values=>["both"], :switch=>"connbytes-dir"}],
     :output => {
       :chain => "INPUT",
       :parameters => {
         "s" => ["1.1.1.1/32"],
       },
       :matches => [
         {:name => "connbytes",
          :options => {
            "!connbytes" => ["10:1000"],
            "connbytes-mode" => ["packets"],
            "connbytes-dir" => ["both"],
          }},
       ],
       :target => nil,
       :target_options => {},
     }},
  ]
  tests.each do |t|
    it "run sample test [#{t[:name]}]" do
      subject.rule(t[:input]).should eq t[:output]
    end
  end
end
