require 'spec_helper'
require 'bundler/audit/scanner'

describe Scanner do
  describe "#scan" do
    let(:bundle)    { 'unpatched' }
    let(:directory) { File.join('spec','bundle',bundle) }

    subject { described_class.new(directory) }

    it "should yield results" do
      results = []

      subject.scan { |result| results << result }

      results.should_not be_empty
    end

    context "when not called with a block" do
      it "should return an Enumerator" do
        subject.scan.should be_kind_of(Enumerable)
      end
    end
  end

  context "when auditing an unpatched bundle" do
    let(:bundle)    { 'unpatched' }
    let(:directory) { File.join('spec','bundle',bundle) }

    subject { described_class.new(directory).scan.to_a }

    it "should match unpatched gems to their advisories" do
      subject[0].gem.name.should == 'actionpack'
      subject[0].gem.version.to_s.should == '3.2.10'
      subject[0].advisory.cve.should == '2013-0156'
    end
  end

  context "when auditing a secure bundle" do
    let(:bundle)    { 'secure' }
    let(:directory) { File.join('spec','bundle',bundle) }

    subject { described_class.new(directory).scan.to_a }

    it "should print nothing when everything is fine" do
      subject.should be_empty
    end
  end
end
