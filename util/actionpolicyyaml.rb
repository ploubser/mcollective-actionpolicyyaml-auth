# yamlpolicy is an extension of the actionpolicy rbac implementation.
# It attempts to simplify the creation of policy files be parsing
# yaml as input, allowing policies to be expressed as data.
#
# Example file :
#   /etc/mcollective/policies/rpcutil.yaml
#
#   ---
#   default :deny
#   action: get_fact
#     - caller: uid=500
#       policy: allow
#       facts: arch=x86
#       classes: ["apache", "webserver"]
#       parameters: fact=arch

require 'yaml'

module MCollective
  module Util
    class ActionPolicyYaml
      attr_accessor :config, :allow_unconfigured, :configdir, :agent
      attr_accessor :caller, :action, :parameters

      def self.authorize(request)
        ActionPolicyYaml.new(request).authorize_request
      end

      def initialize(request)
        @config = Config.instance
        @agent = request.agent
        @caller = request.caller
        @action = request.action
        @parameters = request.data
        @allow_unconfigured = Util.str_to_bool(@config.pluginconf.fetch('yamlpolicy.allow_unconfigured', 'n'))
        @configdir = @config.configdir
      end

      def authorize_request
        # Lookup and load the yaml policy object
        policy = load_policy_file(lookup_policy_file)

        # Found policy file
        if policy
          check_policy(policy)
        else
          # Didn't find anything but we got allow_unconfigured so thats okay
          if @allow_unconfigured
            return true
          # Didn't find anything and we dont' have allow_unconfigured. Fail
          else
            deny('Denying. Could not find a policy file for agent %s and allow_unconfigured=%s' % @agent, @allow_unconfigured)
          end
        end
      end

      private
      # Load and return the policy object
      def load_policy_file(policy_file)
        if policy_file
          Log.info('Loading policy file %s' % policy_file)
          begin
            return YAML.load_file(policy_file)
          rescue ArgumentError => e
            deny('Cannot parse policy file. Reason - %s' % e)
          end
        end
      end

      # Lookup the full path of the policy file. If an agent has a corresponding
      # policy file, return it. If not, check to see if there is a default policy
      # file. If neither of these files exist, we return nil.
      def lookup_policy_file
        # Check if agent has a policy file
        policyfile = File.join(@configdir, 'policies', '%s.yaml' % @agent)
        Log.debug('Trying to load policy file %s' % policyfile)
        return policyfile if File.exists?(policyfile)

        # Lookup a default policy file.
        Log.debug('Policy file %s does not exist. Checking if default policy is enabled' % policyfile)

        if Util.str_to_bool(@config.pluginconf.fetch('actionpolicyyaml.enable_default', 'n'))
          default_name = @config.pluginconf.fetch('actionpolicyyaml.default_name', 'default')
          default_file = File.join(@configdir, 'policies', '%s.yaml' % default_name)
          Log.debug('Trying to load default policy file %s' % default_file)

          return default_file if File.exists?(default_file)
        end

        # No policy files have been identified. Log at info and move on.
        Log.info('Could not find any policy files.')
        nil
      end

      # Check the policy and determine authentication status
      # If policy is nil, return true.
      # If the checks return true and allow is true, return true
      # If the checks return false and allow is true, return false
      # If the checks are true and allow is false, return false
      # If the checks are false and allow is false, return true
      def check_policy(policy)
        if policy
          allow = (policy['policy'] == 'allow') ? true : false
          return allow == (check_restriction(policy['caller'], 'fact') &&
                           check_restriction(policy['classes'], 'class') &&
                           check_restriction(policy['compound'], 'compound') &&
                           check_restriction(policy['params'], 'param'))
        end

        true
      end

      def check_restriction(restrictions, lookup_type = 'fact')
        result = false

        if !restrictions
          result = true
        elsif restrictions.is_a? Array
          result = restrictions.reduce(true) { |x,y| x && self.send("lookup_#{lookup_type}", y) }
        elsif restrictions.is_a? String
          result = self.send("lookup_#{lookup_type}", restrictions)
        end

        result
      end

      def lookup_param(param)
        return true if param == '*'

        if param =~ /(\w+)=(.+)/
          lv = $1
          rv = $2

          return @parameters[lv] == rv
        else
          Log.warn("Malform parameter found. Expecting parameters like 'param=value'")
          return false
        end
      end

      def lookup_fact(fact)
        return true if fact == '*'

        if fact =~ /(.+)(<|>|=|<=|>=)(.+)/
          lv = $1
          sym = $2
          rv = $3
          sym = '==' if sym == '='

          return (Util.get_fact(lv)).send(sym, rv)
        else
          Log.warn("Malformed fact found. Expecting fact like 'fact(<|>|=|<=|>=)value'")
          return false
        end
      end

      def lookup_class(klass)
        return true if klass == '*'

        if klass =~ /^\w+$/
          return Util.has_cf_class?(klass)
        else
          Log.warn("Malformed class found. Expecting class like '/\w+/'")
          return false
        end
      end

      def lookup_compound(compound)
        stack = Matcher.create_compound_callstack(list)

        begin
          stack.map!{ |item| eval_statement(item) }
        rescue => e
          Log.debug(e.to_s)
          return false
        end

        eval(stack.join(' '))
      end

      # Evalute a compound statement and return its truth value
      def eval_statement(statement)
        token_type = statement.keys.first
        token_value = statement.values.first

        return token_value if (token_type != 'statement' && token_type != 'fstatement')

        if token_type == 'statement'
            return lookup(token_value)
        elsif token_type == 'fstatement'
          begin
            return Matcher.eval_compound_fstatement(token_value)
          rescue => e
            Log.warn("Could not call Data function in policy file: #{e}")
            return false
          end
        end
      end

      def lookup(token)
        if token =~  /(.+)(<|>|=|<=|>=)(.+)/
          return lookup_fact(token)
        else
          return lookup_class(token)
        end
      end

      def deny(logline)
        Log.info(logline)
        raise(RPCAborted, 'You are not authorized to call this agent or action.')
      end
    end
  end
end
