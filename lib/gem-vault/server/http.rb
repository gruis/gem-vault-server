require "sinatra"
require "sinatra/reloader"
require "sinatra/json"
require "warden"
require "rack/flash"
require "oj"
require "json"

require "gem-vault/server"
require "gem-vault/server/user"
require "gem-vault/server/gem"
require "gem-vault/ext/oj"

module GemVault
  module Server
    class Http < Sinatra::Base

      NosRecord::Model.default_connection = NosRecord::Connection::LevelDB.new("gem-vault.ldb")
      # TODO don7t send a session cookie when the request includes an Authorization header
      use Rack::Session::Cookie, secret: "3rd Rock from the Sun Rocks"
      use Rack::Flash, accessorize: [:error, :success]

      register Sinatra::Reloader

      set :root, Dir.pwd
      set :json_encoder, Oj
      helpers Sinatra::JSON

      use Warden::Manager do |config|
        config.serialize_into_session{|user| user.id }
        config.serialize_from_session{|id| User.get(id) }
        config.scope_defaults :default,
          strategies: [:apikey],
          action: 'unauthenticated'
        config.failure_app = self
      end

      Warden::Manager.before_failure do |env,opts|
        env['REQUEST_METHOD'] = 'POST'
      end

      Warden::Strategies.add(:apikey) do
        def valid?
          $stderr.puts "checking for api key"
          env['HTTP_AUTHORIZATION']
        end

        def authenticate!
          apikey = ApiKey.get(env['HTTP_AUTHORIZATION'])
          apikey ? success!(apikey.user) : fail!
        end
      end

      Warden::Strategies.add(:password) do
        def flash
          env['x-rack.flash']
        end

        def valid?
          params['user'] && params['user']['username'] && params['user']['password']
        end

        def authenticate!
          if (user = User.get(params['user']['username'])).nil?
            fail!("The username you entered does not exist.")
            flash.error = ""
          elsif user.authenticate(params['user']['password'])
            flash.success = "Successfully Logged In"
            success!(user)
          else
            fail!("Could not log in")
          end
        end
      end # Warden::Strategies.add(:password)


      def warden
        env['warden']
      end

      def warden_opts
        env['warden.options']
      end

      def attempted_path
        warden_opts && warden_opts[:attempted_path]
      end

      def authenticated?
        warden.authenticated?
      end

      def must_auth
        warden.authenticate!
      end

      def authenticate!
        $stderr.puts "authentication failed for: #{attempted_path}"
        session[:return_to] = attempted_path
        flash.error = warden.message || "Login required"
        redirect '/login'
      end

      def user
        warden.user
      end

      def json?(ext = nil)
        request.accept?('json') || (ext && ext == "json")
      end

      get '/login' do
        erb :login
      end

      post '/login' do
        warden.authenticate!
        flash.success = warden.message
        redirect(session[:return_to] || '/')
      end

      post '/unauthenticated' do
        authenticate!
      end

      get '/logout' do
        warden.logout
        flash.success = 'Successfully logged out'
        redirect '/'
      end

      get '/' do
        return json({}) if json?
        erb :index
      end

      get '/index.*' do |ext|
        return json({}) if json?(ext)
        erb :index
      end

      get '/protected' do
        must_auth
        erb :protected
      end

      get '/api/v1/gems/:name.:ext' do |name, ext|
        must_auth
        gem = Server::Gem.each(name).sort(&:version).first
        data = {
          'name'              => gem.name,
          'downloads'         => 0,
          'version'           => gem.version.version,
          'version_downloads' => 0,
          'platform'          => gem.platform,
          'authors'           => gem.authors.join(", "),
          'info'              => gem.description,
          'project_uri'       => uri("/gems/#{gem.name}"),
          'gem_uri'           => url("/gems/#{gem.name}-#{gem.version}.gem"),
        }

        [:homepage,
         :wiki,
         :documentation,
         :mailing_list,
         :source_code,
         :bug_tracker
        ].each do |key|
           data["#{key}_uri"] = gem.send(key)
          end
        data['dependencies'] = gem.dependencies

        return json(data) if json?(ext)
        gems.inspect
      end

    end # class::Http < Sinatra::Base
  end # module::Server
end # module::GemVault
