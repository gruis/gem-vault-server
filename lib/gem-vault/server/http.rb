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
          strategies: [:apikey],
          action: 'unauthenticated'
        config.failure_app = self
      end

      Warden::Manager.before_failure do |env,opts|
        env['REQUEST_METHOD'] = 'POST'
      end

      Warden::Strategies.add(:apikey) do
        def valid?
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

      def gem_by_name(name)
        meta = GemMeta.get(name)
        return meta if meta
        gem = Server::Gem.each(name).sort{|b,a| a.version <=> b.version}.first
        return unless gem
        GemMeta.new(:name => name, :version => gem.version.version)
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
        return 404 unless gem = gem_by_name(name)
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
        results = GemMeta.select do |g|
          g.name.start_with?(params[:query]) ||
            g.gem.summary.include?(params[:query]) ||
            g.gem.description.include?(params[:query])
        end.map(&:to_hash)
        return json(results) if json?(ext)
        results
      end

    end # class::Http < Sinatra::Base
  end # module::Server
end # module::GemVault
