# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  # Metadata
  s.name        = "iptables"
  s.version     = "0.0.1"
  s.authors     = ["Ken Barber"]
  s.email       = ["ken@bob.sh"]
  s.homepage    = "https://github.com/kbarber/ruby-iptables"
  s.summary     = "iptables-save encoder/decoder"

  # Manifest
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*_spec.rb`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # Dependencies
  s.required_ruby_version = '>= 1.8.7'
  s.add_runtime_dependency "json"
end
