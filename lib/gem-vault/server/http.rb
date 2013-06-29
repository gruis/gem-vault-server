require "sinatra"
require "sinatra/reloader"
require "sinatra/json"
require "warden"
require "rack/flash"
require "oj"
require "json"

require "gem-vault/server"
require "gem-vault/server/user"
require "gem-vault/server/gem-meta"
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
          strategies: [:apikey, :password, :basic],
          action: 'unauthenticated'
        config.failure_app = self
      end

      Warden::Manager.before_failure do |env,opts|
        env['REQUEST_METHOD'] = 'POST'
      end

      Warden::Strategies.add(:apikey) do
        def valid?
          env['HTTP_AUTHORIZATION'] && !env['HTTP_AUTHORIZATION'].start_with?("Basic ")
        end

        def authenticate!
          apikey = ApiKey.get(env['HTTP_AUTHORIZATION'])
          apikey ? success!(apikey.user) : fail!
        end
      end # Warden::Strategies.add(:apikey)

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

      Warden::Strategies.add(:basic) do
        def auth
          @auth ||= Rack::Auth::Basic::Request.new(env)
        end

        def valid?
          auth.provided? && auth.basic? && auth.credentials
        end

        def authenticate!
          user = User.get(auth.credentials.first)
          user && user.authenticate(auth.credentials.last) ?
            success!(user)  : custom!(unauthorized)
        end

        def store?
          false
        end

        def unauthorized
          [
            401,
            {
              'Content-Type' => 'text/plain',
              'Content-Length' => '0',
              'WWW-Authenticate' => %(Basic realm="realm")
            },
            []
            ]
        end
      end # Warden::Strategies.add(:basic)


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

      def gems_by_keyword(query)
        GemMeta.select do |g|
          g.name.start_with?(params[:query]) ||
            g.gem.summary.include?(params[:query]) ||
            g.gem.description.include?(params[:query])
        end
      end

      def gems_by_owner(owner)
        GemMeta.select do |g|
          g.owners.include?(owner)
        end
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
        return 404 unless gem = GemMeta.by_name(name)
        gem.save if gem.new?
        meta = gem.to_hash
        ['project_uri', 'gem_uri'].each do |key|
          meta[key] = uri(meta[key])
        end
        return json(meta) if json?(ext)
        meta
      end

      get '/api/v1/search.:ext' do |ext|
        must_auth
        # TODO retain an index
        results = gems_by_keyword(params[:query]).map(&:to_hash)
        return json(results) if json?(ext)
        results
      end

      # List all gems that you own.
      get '/api/v1/gems.:ext' do |ext|
        must_auth
        results = gems_by_owner(user).map(&:to_hash)
        return json(results) if json?(ext)
        results
      end

      # View all owners of a gem. These users can all push to this gem.
      get '/api/v1/gems/:name/owners.:ext' do |name, ext|
        must_auth
        gem    = GemMeta.by_name(name)
        owners = Hash[gem.owners.map {|e| ['email', e.email]}]
        return json(owners) if json?(ext)
        owners
      end

      # View all gems for a user. This is all the gems a user can push to.
      get  '/api/v1/owners/:name/gems.:ext' do |name, ext|
        must_auth
        return 404 unless u = User.get(name)
        results = u.gems.map(&:to_hash)
        return json(results) if json?(ext)
        results
      end

      # Add an owner to a RubyGem you own, giving that user permission to
      # manage it.
      post '/api/v1/gems/:name/owners' do |name|
        must_auth
        return 404 unless gem = GemMeta.by_name(name)
        return 401 unless user.own?(gem)
        # TODO verify that params[:email] is not nil
        return 404 unless owner = User.get(:email => params[:email])
        gem.add_owner(owner)
        gem.save
        return json(:status => :ok) if json?(ext)
        "Owner added successfully."
      end

      # Remove a user’s permission to manage a RubyGem you own.
      delete '/api/v1/gems/:name/owners' do |name|
        must_auth
        return 404 unless gem = GemMeta.by_name(name)
        return 401 unless user.own?(gem)
        # TODO verify that params[:email] is not nil
        return 404 unless owner = User.get(:email => params[:email])
        gem.del_owner(owner)
        gem.save
        return json(:status => :ok) if json?(ext)
        "Owner removed successfully."
      end

      # Retrieve your API key using HTTP basic auth.
      get  '/api/v1/api_key.:ext' do |ext|
        must_auth
        data = {
          'gemvault_api_key' => (user.api_key || user.gen_api_key.api_key).key
        }
        return json(data) if json?(ext)
        data
      end

    end # class::Http < Sinatra::Base
  end # module::Server
end # module::GemVault
