#!/usr/bin/env rspec

require 'spec_helper'
require File.join(File.dirname(__FILE__), '../../', 'util', 'actionpolicyyaml.rb')

module MCollective
  module Util
    describe ActionPolicyYaml do

      let(:request) do
        req = mock
        req.stubs(:agent).returns("agent")
        req.stubs(:caller).returns("uid=500")
        req.stubs(:action).returns("rspec")
        req.stubs(:data).returns({"foo" => "bar"})
        req
      end

      let(:config) do
        conf = mock
        conf.stubs(:pluginconf).returns({})
        conf.stubs(:configdir).returns("/rspec")
        conf
      end

      before do
        Config.stubs(:instance).returns(config)
        Log.stubs(:debug)
        @auth = ActionPolicyYaml.new(request)
      end

      describe '#authorize' do
        it 'should create the ActionPolicyYaml Object and call #authorize_request' do
          auth = mock
          auth.expects(:authorize_request)
          ActionPolicyYaml.expects(:new).with(request).returns(auth)
          ActionPolicyYaml.authorize(request)
        end
      end

      describe '#initialize' do
      end

      describe '#authorize_request' do
      end

      describe '#load_policy_file' do
        it 'should load the yaml file as a ruby hash' do
          Log.stubs(:info)
          YAML.stubs(:load_file).with('/rspec/policies/agent.yaml').returns({})
          @auth.__send__(:load_policy_file, '/rspec/policies/agent.yaml').should == {}
        end

        it 'should log at warn and fail if it cannot parse the yaml file' do
          Log.stubs(:info)
          YAML.stubs(:load_file).with('/rspec/policies/agent.yaml').raises(ArgumentError, 'error')
          @auth.expects(:deny).with('Cannot parse policy file. Reason - error')
          @auth.__send__(:load_policy_file, '/rspec/policies/agent.yaml')
        end
      end

      describe '#lookup_policy_file' do
        it 'should return the name of the policy file for an agent' do
          File.stubs(:exists?).with('/rspec/policies/agent.yaml').returns(true)
          @auth.__send__(:lookup_policy_file).should == '/rspec/policies/agent.yaml'
        end

        it 'should return the name of the default policy file' do
          File.stubs(:exists?).with('/rspec/policies/agent.yaml').returns(false)
          File.stubs(:exists?).with('/rspec/policies/default.yaml').returns(true)
          config.pluginconf['actionpolicyyaml.enable_default'] = 'y'
          @auth.__send__(:lookup_policy_file).should == '/rspec/policies/default.yaml'
        end

        it 'should log and return nil if no policy file was found' do
          File.stubs(:exists?).with('/rspec/policies/agent.yaml').returns(false)
          Log.expects(:info)
          @auth.__send__(:lookup_policy_file).should == nil
        end
      end

      describe '#check_policy' do
        it 'should return true if no policy has been specified' do
          @auth.__send__(:check_policy, nil).should == true
        end

        it 'should return true if the policies allow the call' do
          @auth.stubs(:check_restriction).returns(true)
          @auth.__send__(:check_policy, {'policy' => 'allow'}).should == true
        end

        it 'should return false if the policies do not allow the call' do
          @auth.stubs(:check_restriction).returns(false)
          @auth.__send__(:check_policy, {'policy' => 'allow'}).should == false
        end
      end

      describe '#check_restrictions' do
        it 'should return true if there are no restrictions' do
          @auth.send('check_restriction', nil).should == true
        end

        it 'should check restrictions when restrictions is a string' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'fact').should == true
        end

        it 'should check restrictrions when restrictions is an array' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.expects(:send).with('lookup_fact', 'bar=baz').returns(true)
          @auth.__send__('check_restriction', ['foo=bar', 'bar=baz'], 'fact').should == true
        end

        it 'should check facts' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'fact').should == true
        end

        it 'should check classes' do
          @auth.expects(:send).with('lookup_class', 'rspec').returns(true)
          @auth.__send__('check_restriction', 'rspec', 'class').should == true
        end

        it 'should check params' do
          @auth.expects(:send).with('lookup_param', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'param').should == true
        end
      end

      describe '#check_policy' do
        it 'should return true if no policy has been specified' do
          @auth.__send__(:check_policy, nil).should == true
        end

        it 'should return true if the policies allow the call' do
          @auth.stubs(:check_restriction).returns(true)
          @auth.__send__(:check_policy, {'policy' => 'allow'}).should == true
        end

        it 'should return false if the policies do not allow the call' do
          @auth.stubs(:check_restriction).returns(false)
          @auth.__send__(:check_policy, {'policy' => 'allow'}).should == false
        end
      end

      describe '#check_restrictions' do
        it 'should return true if there are no restrictions' do
          @auth.send('check_restriction', nil).should == true
        end

        it 'should check restrictions when restrictions is a string' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'fact').should == true
        end

        it 'should check restrictrions when restrictions is an array' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.expects(:send).with('lookup_fact', 'bar=baz').returns(true)
          @auth.__send__('check_restriction', ['foo=bar', 'bar=baz'], 'fact').should == true
        end

        it 'should check facts' do
          @auth.expects(:send).with('lookup_fact', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'fact').should == true
        end

        it 'should check classes' do
          @auth.expects(:send).with('lookup_class', 'rspec').returns(true)
          @auth.__send__('check_restriction', 'rspec', 'class').should == true
        end

        it 'should check params' do
          @auth.expects(:send).with('lookup_param', 'foo=bar').returns(true)
          @auth.__send__('check_restriction', 'foo=bar', 'param').should == true
        end

        it 'should check compound statements' do
          @auth.expects(:send).with('lookup_compound', 'foo=bar and rspec').returns(true)
          @auth.__send__('check_restriction', 'foo=bar and rspec', 'compound').should == true
        end
      end

      describe '#lookup_param' do
        it 'should return true if param is *' do
          @auth.__send__('lookup_param', '*').should == true
        end

        it 'should return true if the param is not restricted' do
          @auth.__send__('lookup_param', 'foo=bar').should == true
        end

        it 'should return false if the param is restricted' do
          @auth.__send__('lookup_param', 'foo=baz').should == false
        end

        it 'should log and return false if the param is malformed' do
          Log.expects(:warn)
          @auth.__send__('lookup_param', 'foobaz').should == false
        end
      end

      describe '#lookup_fact' do
        it 'should return true if the fact is *' do
          @auth.__send__('lookup_fact', '*').should == true
        end

        it 'should return true if the fact is present' do
          Util.stubs(:get_fact).with('foo').returns('bar')
          @auth.__send__('lookup_fact', 'foo=bar').should == true
        end

        it 'should return false if the fact is not present' do
          Util.stubs(:get_fact).with('foo').returns('baz')
          @auth.__send__('lookup_fact', 'foo=bar').should == false
        end

        it 'should log and return false if the fact is malformed' do
          Log.expects(:warn)
          @auth.__send__('lookup_fact', 'foobaz').should == false
        end
      end

      describe '#lookup_class' do
        it 'should return true if the class is *' do
          @auth.__send__('lookup_class', '*').should == true
        end

        it 'should return true if the class is present' do
          Util.stubs(:has_cf_class?).with('rspec').returns(true)
          @auth.__send__('lookup_class', 'rspec').should == true
        end

        it 'should return false if the class is not present' do
          Util.stubs(:has_cf_class?).with('rspec').returns(false)
          @auth.__send__('lookup_class', 'rspec').should == false
        end

        it 'should log and return false if the class is malformed' do
          Log.expects(:warn)
          @auth.__send__('lookup_class', 'rspe=f').should == false
        end
      end

      describe '#lookup_compound' do
      end

      describe '#eval_statement' do
      end

      describe '#lookup' do
        it 'should lookup a fact' do
          @auth.stubs(:lookup_fact).with('foo=bar').returns(true)
          @auth.__send__(:lookup, 'foo=bar').should == true
        end

        it 'should lookup a class' do
          @auth.stubs(:lookup_class).with('rspec').returns(true)
          @auth.__send__(:lookup, 'rspec').should == true
        end
      end

      describe '#deny' do
        it 'should log the debug message and fail' do
          Log.expects(:info).with('failure')
          expect{
            @auth.__send__(:deny, 'failure')
          }.to raise_error RPCAborted
        end
      end
    end
  end
end
