require 'rubygems'
SPEC = Gem::Specification.new do |s|
  s.name = "pNet-DNS"
  s.version = "1.0.2"
  s.authors = ["AlexD"]
  s.email = "alexd@nominet.org.uk"
  s.homepage = "http://rubyforge.org/projects/pnet-dns/"
  s.platform = Gem::Platform::RUBY
  s.summary = "Ruby port of perl Net::DNS"
  candidatestest = Dir.glob("test/**/*")
  candidateslib = Dir.glob("lib/**/*")
  candidatesdoc = Dir.glob("doc/**/*")
   candidates = candidatestest + candidateslib + candidatesdoc
  s.files = candidates.delete_if do |item|
                      item.include?("CVS") || item.include?("rdoc") ||
                         item.include?("svn")
                end
  s.autorequire="Net/DNS"
  s.test_file = "test/ts_offline.rb"
  s.has_rdoc = true
  s.extra_rdoc_files = ["README"]
end

