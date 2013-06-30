# encoding: BINARY
require "sinatra"
require "sinatra/reloader"
require "sinatra/json"
require "warden"
require "rack/flash"
require "oj"
require "json"

require "gem-vault/server"
require "gem-vault/server/error"
require "gem-vault/server/user"
require "gem-vault/server/gem-meta"
require "gem-vault/server/indexer"
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
      set :gemroot, File.join(settings.root, "var")
      set :indexer, Indexer.new(settings.gemroot)
      set :json_encoder, Oj
      helpers Sinatra::JSON

      use Warden::Manager do |config|
        config.serialize_into_session{|user| user.id }
        config.serialize_from_session{|id| User.get(id) }
        config.scope_defaults :default,
          strategies: [:apikey, :apibasic, :password, :basic],
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
          [401, { 'Content-Type' => 'text/plain',
                  'Content-Length' => '0',
                  'WWW-Authenticate' => %(Basic realm="realm")
          }, []]
        end
      end # Warden::Strategies.add(:basic)

      Warden::Strategies.add(:apibasic) do
        def auth
          @auth ||= Rack::Auth::Basic::Request.new(env)
        end

        def valid?
          auth.provided? && auth.basic? &&
            auth.credentials && auth.credentials.first &&
            auth.credentials.last.empty?
        end

        def authenticate!
          (apikey = ApiKey.get(auth.credentials.first)) && (user = apikey.user) ?
            success!(user) :
            custom!(unauthorized)
        end

        def store?
          false
        end

        def unauthorized
          [401, { 'Content-Type' => 'text/plain',
                  'Content-Length' => '0',
                  'WWW-Authenticate' => %(Basic realm="realm")
          }, []]
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

      error GemExists do
        status 409
        msg = "Gem already exists: #{env['sinatra.error'].message}"
        return json(:status => 409, :error => msg) if json?(ext)
        msg
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

      get '/index?.?:ext?' do |ext|
        return json({}) if json?(ext)
        erb :index
      end

      def serve
        send_file File.join(settings.gemroot, *request.path_info),
          :type => response['Content-Type']
      end

      %w[/specs.4.8.gz /latest_specs.4.8.gz /prerelease_specs.4.8.gz ].each do |index|
        get index do
          must_auth
          content_type('application/x-gzip')
          serve
        end
      end

      %w[/quick/Marshal.4.8/*.gemspec.rz /yaml.Z /Marshal.4.8.Z ].each do |deflated_index|
        get deflated_index do
          must_auth
          content_type('application/x-deflate')
          serve
        end
      end

      %w[/yaml /Marshal.4.8 /specs.4.8 /latest_specs.4.8 /prerelease_specs.4.8 ].each do |old_index|
        get old_index do
          must_auth
          serve
        end
      end

      get "/gems/*.gem" do
        must_auth
        serve
      end

      get "/reindex.?:ext?/?" do |ext|
        must_auth
        return 401 unless user.admin?
        # TODO update the index in a delayed job
        if settings.indexer.index
          json?(ext) ? json(:status => :ok) : "Gem index updated"
        else
          json?(ext) ? json(:status => :failed) : "Gem index not updated"
        end
      end

      def attrs_to_bool!(attrs, *keys)
        keys.each do |key|
          if attrs[key]
            attrs[key] = ['true', 'yes', true].include?(attrs[key])
          end
        end
        attrs
      end
      # User management

      def create_user(id, attrs)
        update_user(User.new(:uid => id), attrs)
      end

      def update_user(u, attrs)
        attrs_to_bool!(attrs, 'admin')
        attrs.each do |key, value|
          u.send("#{key}=", value) if u.respond_to?("#{key}=")
        end
        u.save
        u
      end

      def make_user_hash(u)
        h = u.to_hash
        unless u.id == user.id || user.admin?
          h.delete('password')
          h.delete('api_key')
        end
        h
      end

      get '/users.?:ext?/?' do |ext|
        must_auth
        users = Hash[User.map { |u| [u.id, u.email] }]
        return json(users) if json?(ext)
        users
      end

      get '/user.?:ext?/?' do |ext|
        must_auth
        json?(ext) ? json(make_user_hash(user)) : make_user_hash(user)
      end

      get '/user/:id.?:ext?/?' do |id, ext|
        must_auth
        return 404 unless (u = User.get(id))
        json?(ext) ? json(make_user_hash(u)) : make_user_hash(u)
      end

      put '/user/:id.?:ext?/?' do |id, ext|
        must_auth
        if (u = User.get(id)).nil?
          u = create_user(id, params)
        else
          return 401 unless u.id == user.id || user.admin?
          params.delete('id')
          update_user(u, params)
        end
        json?(ext) ? json(make_user_hash(u)) : make_user_hash(u)
      end

      post '/user.?:ext?/?' do |ext|
        must_auth
        return 409 unless user.admin?
        return 400 unless params['id'] && params['email'] && params['password']
        return 409 if (u = User.get(params['id']))
        u = create_user(params.delete('id'), params)
        link = url("/user/#{u.id}")
        json?(ext) ? json(:link => link) : link
      end

      delete '/user/:id.?:ext?/?' do |id, ext|
        must_auth
        return 409 unless user.admin?
        (u = User.get(params['id'])) && u.delete
        json?(ext) ? json(:status => "ok") : "ok"
      end

      # RubyGems API

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
      get  '/api/v1/api_key.?:ext?/?' do |ext|
        must_auth
        if !user.api_key
          user.gen_api_key.save
        end
        data = { 'gemvault_api_key' => user.api_key.key }
        return json(data) if json?(ext)
        data
      end

      delete '/api/v1/api_key.?:ext?/?' do |ext|
        must_auth
        user.del_api_key
        json?(ext) ? json(:status => :ok) : "Api key removed"
      end

      # Returns an array of gem version
      get '/api/v1/versions/:name.:ext' do |name, ext|
        must_auth
        return 404 unless GemMeta.by_name(name)
        results = Gem.each(name).reverse.map do |gem|
          {
            'authors'         => gem.authors.join(", "),
            'built_at'        => gem.date.strftime("%Y-%m-%dT%H:%M:%SZ") ,
            'description'     => gem.description,
            # TODO track downloads of each verion
            'downloads_count' => 0,
            'number'          => gem.version.version,
            'summary'         => gem.summary,
            'platform'        => gem.platform,
            'prerelease'      => !!gem.version.prerelease?,
            'licenses'        => gem.license
          }
        end
        return json(results) if json?(ext)
        results
      end

      # Submit a gem. Must post a built RubyGem in the request body.
      post '/api/v1/gems' do
        must_auth
        gem = Gem.open(request.body)
        if (meta = GemMeta.by_name(gem.name))
          return 401 if !meta.new? && !user.own?(meta)
          begin
            gem  = Gem.add(gem, request.body)
          rescue Errno::EEXIST  => e
            raise GemExists.new(e.message) unless meta.new?
            $stderr.puts "#{e.message} already exists, but with no metadata"
          end
          meta.gem!

        else
          Gem.add(gem, request.body)
          meta = GemMeta.new(:name => gem.name)
        end

        meta.add_owner(user).save
        user.add_gem(meta).save

        # TODO update the index in a delayed job
        settings.indexer.index
        # TODO build documentation for the gem

        return json(:name => meta.name, :version => meta.version) if json?
        "Successfully registered gem: #{meta.name} (#{gem.version})"
      end

      # Remove a gem from the index. Platform is optional.
      # @example
      #   $ curl -X DELETE -H 'Authorization:701243f217cdf23b1370c7b66b65ca97' \
      #          -d 'gem_name=bills' -d 'version=0.0.1' \
      #          -d 'platform=x86-darwin-10' \
      #          https://rubygems.org/api/v1/gems/yank
      delete '/api/v1/gems/yank' do
        must_auth
        return 404 if (meta = GemMeta.by_name(params['gem_name'])).nil?
        return 401 unless user.own?(meta)
        return 501 # TODO create a yank meta
        return 404 if (gem = Gem.by_version(meta.nam, params['version'])).nil?
        gem.yank
        meta.gem!
        meta.save
        return json(:name => meta.name, :version => param['version']) if json?
        "Successfully yanked gem: #{meta.name} (#{params['version']})"
      end

      # Update a previously yanked gem back into RubyGems.org’s index. Platform is optional.
      # @example
      #   $ curl -X PUT -H 'Authorization:701243f217cdf23b1370c7b66b65ca97' \
      #          -d 'gem_name=bills' -d 'version=0.0.1' \
      #          -d 'platform=x86-darwin-10' \
      #          https://rubygems.org/api/v1/gems/unyank
      put '/api/v1/gems/unyank' do
        must_auth
        return 404 if (meta = GemMeta.by_name(params['gem_name'])).nil?
        return 401 unless user.own?(meta)
        return 501 # TODO create a yank meta
        return json(:name => meta.name, :version => param['version']) if json?
        "Successfully unyanked gem: #{meta.name} (#{params['version']})"
      end

    end # class::Http < Sinatra::Base
  end # module::Server
end # module::GemVault
